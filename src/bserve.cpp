// bserve.cpp
//
// Track 1 - binary HTTP server.
//
//   ./bserve <root-dir> <port>
//   ./bserve ./www 9000
//
// Step 3 scope:
//   * turn the Step 2 stub into a real request parser
//   * validate frame headers (stream id, reserved flag bits, frame ordering)
//   * validate the serialized header block inside HEADERS frames
//   * skip unknown frame types cleanly using their declared payload length
//   * answer a malformed request with a 400 response instead of crashing
//
// File mapping / 200 / 404 live in Step 4. Here a well-formed request is parsed
// and logged, then the connection waits for the next one.
//
#include "protocol.hpp"
#include "frame_io.hpp"

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
// Response building
// ---------------------------------------------------------------------------
// A response is a HEADERS frame (Status / Content-Type / Content-Length)
// followed by a DATA frame carrying the body. If the body is empty we can put
// END_STREAM on the HEADERS frame and skip DATA entirely.
//
bool sendResponse(int fd, int status, const std::string& content_type,
                  const std::string& body) {
    std::vector<uint8_t> hblock;
    try {
        appendHeader(hblock, "Status", std::to_string(status));
        appendHeader(hblock, "Content-Type", content_type);
        appendHeader(hblock, "Content-Length", std::to_string(body.size()));
    } catch (const std::exception&) {
        return false;   // a field exceeded the 16-bit length; nothing to send
    }

    if (body.empty()) {
        // Single frame, stream done.
        return writeFrameVec(fd, FRAME_HEADERS, FLAG_END_STREAM, 0, hblock);
    }

    if (!writeFrameVec(fd, FRAME_HEADERS, FLAG_NONE, 0, hblock)) return false;
    return writeFrame(fd, FRAME_DATA, FLAG_END_STREAM, 0, body.data(),
                      static_cast<uint32_t>(body.size()));
}

bool sendError(int fd, int status, const std::string& message) {
    return sendResponse(fd, status, "text/plain", message + "\n");
}

// ---------------------------------------------------------------------------
// Per-request parse state
// ---------------------------------------------------------------------------
// One request = HEADERS frame (optionally extended by more HEADERS frames and
// DATA frames) terminated by the END_STREAM flag.
//
struct RequestState {
    bool got_headers = false;      // at least one HEADERS frame seen
    std::vector<Header> headers;   // accumulated name/value pairs

    void reset() {
        got_headers = false;
        headers.clear();
    }
};

void logRequest(const RequestState& req) {
    std::fprintf(stderr, "[bserve] request complete (%zu headers):\n",
                 req.headers.size());
    for (const auto& kv : req.headers)
        std::fprintf(stderr, "           %s: %s\n",
                     kv.name.c_str(), kv.value.c_str());
    // Step 4 will map Method/Path/Host to a file here.
}

// ---------------------------------------------------------------------------
// Frame dispatch
// ---------------------------------------------------------------------------
// Returns false if the connection must be closed (fatal, unrecoverable), true
// to keep serving (including after a recoverable 400).
//
bool handleFrame(int fd, const FrameHeader& h,
                 const std::vector<uint8_t>& payload, RequestState& req) {
    // --- Common header-field validation for every frame -------------------
    if (h.stream_id != 0) {
        sendError(fd, 400, "bad request: non-zero stream id");
        req.reset();
        return true;   // recoverable: whole payload was consumed
    }
    if ((h.flags & ~FLAG_END_STREAM) != 0) {
        sendError(fd, 400, "bad request: reserved flag bits set");
        req.reset();
        return true;
    }

    // --- Unknown frame type: skip its payload and carry on -----------------
    // The bytes are already read by readFrame(), so "skipping" is simply an
    // early return. We must NOT close the connection or reset the request.
    if (!isKnownFrameType(h.frame_type)) {
        std::fprintf(stderr,
                     "[bserve] skipping unknown frame type 0x%02x (%u bytes)\n",
                     h.frame_type, h.payload_length);
        return true;
    }

    const bool end_stream = (h.flags & FLAG_END_STREAM) != 0;

    switch (h.frame_type) {
        case FRAME_HEADERS: {
            std::vector<Header> parsed;
            if (!parseHeaderBlock(payload.data(), payload.size(), parsed)) {
                sendError(fd, 400, "bad request: malformed header block");
                req.reset();
                return true;
            }
            for (auto& kv : parsed) req.headers.push_back(std::move(kv));
            req.got_headers = true;
            break;
        }

        case FRAME_DATA: {
            if (!req.got_headers) {
                sendError(fd, 400, "bad request: DATA before HEADERS");
                req.reset();
                return true;
            }
            // Step 4: request bodies would be accumulated here.
            break;
        }

        case FRAME_RST: {
            // Peer aborted the exchange; drop partial state, stay connected.
            req.reset();
            return true;
        }

        default:
            break;   // unreachable: filtered by isKnownFrameType
    }

    if (end_stream) {
        if (!req.got_headers) {
            sendError(fd, 400, "bad request: stream ended without HEADERS");
            req.reset();
            return true;
        }
        logRequest(req);
        req.reset();
    }
    return true;
}

// ---------------------------------------------------------------------------
// Per-connection loop: KEEP THE CONNECTION OPEN across many requests.
// ---------------------------------------------------------------------------
void serveConnection(int fd) {
    RequestState req;

    while (g_running) {
        FrameHeader h;
        std::vector<uint8_t> payload;
        std::string err;

        FrameStatus st = readFrame(fd, h, payload, MAX_PAYLOAD_LENGTH, &err);
        if (st == FrameStatus::CleanEof) break;

        if (st == FrameStatus::Error) {
            // Either a socket error or an over-long declared length. We cannot
            // resynchronize the byte stream, so tell the peer and close.
            std::fprintf(stderr, "[bserve] frame error: %s\n", err.c_str());
            sendError(fd, 400, "bad request: " + err);
            break;
        }

        if (!handleFrame(fd, h, payload, req)) break;
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
int createListenSocket(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::perror("[bserve] socket");
        return -1;
    }

    int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        std::perror("[bserve] setsockopt(SO_REUSEADDR)");
        ::close(fd);
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

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

    // sigaction with sa_flags = 0 (NO SA_RESTART) so a blocking accept()
    // returns EINTR and the loop sees g_running == 0.
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

    while (g_running) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int client = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer),
                              &peer_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            std::perror("[bserve] accept");
            continue;
        }

        char peer_ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        std::fprintf(stderr, "[bserve] connection from %s:%u\n",
                     peer_ip, ntohs(peer.sin_port));

        serveConnection(client);

        ::close(client);
        std::fprintf(stderr, "[bserve] connection closed\n");
    }

    ::close(listen_fd);
    std::fprintf(stderr, "[bserve] shutting down\n");
    return 0;
}
