// bserve.cpp
//
// Track 1 - binary HTTP server.
//
//   ./bserve <root-dir> <port>
//   ./bserve ./www 9000
//
// Step 2 scope: wire up the network plumbing only.
//   * parse + validate arguments
//   * create a TCP listening socket (SO_REUSEADDR)
//   * accept connections, one at a time
//   * hold each connection OPEN and read frames in a persistent loop until
//     the peer closes it or a fatal error occurs
//
// Frame *interpretation* (validation, file mapping, responses) lands in later
// steps; here we only frame the bytes and hand them to a stub.
//
#include "protocol.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace bitmid;

namespace {

// Set to 0 by SIGINT/SIGTERM so the accept/read loops can unwind cleanly.
volatile std::sig_atomic_t g_running = 1;

void onSignal(int /*signum*/) {
    g_running = 0;
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------
// recv()/send() may return short counts and may be interrupted by signals.
// These wrappers loop until the requested number of bytes is transferred.
//
// Return true on full transfer, false on EOF or a non-retryable error.
// `out_eof` (optional) distinguishes a clean shutdown from a hard error.
//
bool readFull(int fd, void* buf, std::size_t n, bool* out_eof = nullptr) {
    auto* p = static_cast<uint8_t*>(buf);
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd, p + got, n - got, 0);
        if (r == 0) {                       // orderly shutdown by peer
            if (out_eof) *out_eof = true;
            return false;
        }
        if (r < 0) {
            if (errno == EINTR) continue;   // retry after a signal
            if (out_eof) *out_eof = false;
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    return true;
}

[[maybe_unused]] bool writeFull(int fd, const void* buf, std::size_t n) {
    const auto* p = static_cast<const uint8_t*>(buf);
    std::size_t sent = 0;
    while (sent < n) {
        ssize_t r = ::send(fd, p + sent, n - sent, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        sent += static_cast<std::size_t>(r);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Frame handling (stub)
// ---------------------------------------------------------------------------
// Step 3 replaces this with real validation, unknown-type skipping, and
// malformed-frame handling. For now we log what arrived and keep going so the
// persistent loop is exercised end to end.
//
void handleFrame(int /*fd*/, const FrameHeader& h,
                 const std::vector<uint8_t>& payload) {
    std::fprintf(stderr,
                 "[bserve] frame type=0x%02x flags=0x%02x stream=%u len=%u\n",
                 h.frame_type, h.flags, h.stream_id, h.payload_length);
    (void)payload;
}

// ---------------------------------------------------------------------------
// Per-connection loop: KEEP THE CONNECTION OPEN across many requests.
// ---------------------------------------------------------------------------
void serveConnection(int fd) {
    while (g_running) {
        // 1) Read the fixed 8-byte frame header.
        uint8_t header_bytes[8];
        bool eof = false;
        if (!readFull(fd, header_bytes, sizeof(header_bytes), &eof)) {
            if (!eof) std::perror("[bserve] recv header");
            break;  // clean close or error: drop this connection, keep server up
        }

        FrameHeader h = parseFrameHeader(header_bytes);

        // 2) Sanity-check the declared length before allocating.
        if (h.payload_length > MAX_PAYLOAD_LENGTH) {
            std::fprintf(stderr,
                         "[bserve] payload length %u exceeds cap, closing\n",
                         h.payload_length);
            break;
        }

        // 3) Read exactly payload_length bytes (none if zero).
        std::vector<uint8_t> payload(h.payload_length);
        if (h.payload_length != 0) {
            if (!readFull(fd, payload.data(), payload.size(), &eof)) {
                if (!eof) std::perror("[bserve] recv payload");
                break;
            }
        }

        // 4) Dispatch. Connection intentionally stays open afterwards.
        handleFrame(fd, h, payload);
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
struct Options {
    std::string root_dir;
    uint16_t    port = 0;
};

bool isDirectory(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool parseArgs(int argc, char** argv, Options& opts) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <root-dir> <port>\n", argv[0]);
        return false;
    }
    opts.root_dir = argv[1];

    if (!isDirectory(opts.root_dir)) {
        std::fprintf(stderr, "[bserve] root directory not found: %s\n",
                     opts.root_dir.c_str());
        return false;
    }

    char* end = nullptr;
    errno = 0;
    long p = std::strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || p < 1 || p > 65535) {
        std::fprintf(stderr, "[bserve] invalid port: %s\n", argv[2]);
        return false;
    }
    opts.port = static_cast<uint16_t>(p);
    return true;
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------
// Create, bind and listen a TCP socket. Returns the fd, or -1 on error.
//
int createListenSocket(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::perror("[bserve] socket");
        return -1;
    }

    // Reuse the address so a restart doesn't fail on a lingering TIME_WAIT.
    int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        std::perror("[bserve] setsockopt(SO_REUSEADDR)");
        ::close(fd);
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);      // bind all interfaces
    addr.sin_port = htons(port);                   // network byte order

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("[bserve] bind");
        ::close(fd);
        return -1;
    }

    if (::listen(fd, /*backlog=*/16) < 0) {
        std::perror("[bserve] listen");
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    Options opts;
    if (!parseArgs(argc, argv, opts)) return 1;

    // Install signal handlers so Ctrl-C unwinds cleanly.
    //
    // We use sigaction with sa_flags = 0 (NO SA_RESTART) on purpose: that makes
    // a blocking accept() return EINTR when a signal arrives, which is exactly
    // how the loop below notices g_running == 0. std::signal() would set
    // SA_RESTART and silently restart accept() forever.
    struct sigaction sa{};
    sa.sa_handler = onSignal;   // sa_mask is empty thanks to value-init
    sa.sa_flags = 0;
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    std::signal(SIGPIPE, SIG_IGN);  // a dead peer must not kill the server

    int listen_fd = createListenSocket(opts.port);
    if (listen_fd < 0) return 1;

    std::fprintf(stderr, "[bserve] serving %s on port %u\n",
                 opts.root_dir.c_str(), opts.port);

    // Accept loop. One client at a time is sufficient for this project.
    while (g_running) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int client = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer),
                              &peer_len);
        if (client < 0) {
            if (errno == EINTR) continue;   // signal: re-check g_running
            std::perror("[bserve] accept");
            continue;
        }

        char peer_ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        std::fprintf(stderr, "[bserve] connection from %s:%u\n",
                     peer_ip, ntohs(peer.sin_port));

        serveConnection(client);            // runs until peer closes

        ::close(client);
        std::fprintf(stderr, "[bserve] connection closed\n");
    }

    ::close(listen_fd);
    std::fprintf(stderr, "[bserve] shutting down\n");
    return 0;
}
