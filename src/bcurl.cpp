// bcurl.cpp
//
// Track 2 - binary HTTP client.
//
//   ./bcurl [-v] <host>[:<port>][/<path>]
//   ./bcurl -v localhost:9000/index.html
//
// Step 5 scope:
//   * parse the optional -v flag and the URL argument
//   * resolve the host and open exactly ONE TCP connection
//   * build the binary request frame (HEADERS: Method/Path/Host, END_STREAM)
//   * send that request over the single connection
//
// Step 6 will replace the readResponse() stub below with real response
// handling: verbose hexdumping, body to stdout, and non-zero exit on 4xx/5xx.
//
#include "protocol.hpp"
#include "frame_io.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace bitmid;

namespace {

constexpr uint16_t DEFAULT_PORT = 9000;

// ---------------------------------------------------------------------------
// Options + argument parsing
// ---------------------------------------------------------------------------
struct Options {
    bool        verbose = false;
    std::string host;
    uint16_t    port = DEFAULT_PORT;
    std::string path = "/";
};

void usage(const char* prog) {
    std::fprintf(stderr,
                 "usage: %s [-v] <host>[:<port>][/<path>]\n"
                 "  -v    hex-dump every frame sent and received\n"
                 "  default port %u, default path \"/\"\n",
                 prog, DEFAULT_PORT);
}

// Parse "host", "host:port", "host/path", "host:port/path". An optional
// "scheme://" prefix (e.g. "http://") is accepted and ignored.
bool parseUrl(const std::string& in, std::string& host, uint16_t& port,
              std::string& path) {
    std::string s = in;

    std::size_t scheme = s.find("://");
    if (scheme != std::string::npos) s = s.substr(scheme + 3);
    if (s.empty()) return false;

    // Authority is everything before the first '/'.
    std::size_t slash = s.find('/');
    std::string authority =
        (slash == std::string::npos) ? s : s.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : s.substr(slash);
    if (path.empty()) path = "/";

    // Optional :port (rfind so a stray ':' earlier in the host is not fatal).
    std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        std::string port_str = authority.substr(colon + 1);
        if (host.empty() || port_str.empty()) return false;

        char* end = nullptr;
        long p = std::strtol(port_str.c_str(), &end, 10);
        if (*end != '\0' || p < 1 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } else {
        host = authority;
        port = DEFAULT_PORT;
    }
    return !host.empty();
}

bool parseArgs(int argc, char** argv, Options& opts) {
    std::string url;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") {
            opts.verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return false;
        } else if (url.empty()) {
            url = arg;
        } else {
            std::fprintf(stderr, "[bcurl] unexpected argument: %s\n",
                         arg.c_str());
            return false;
        }
    }
    if (url.empty()) {
        usage(argv[0]);
        return false;
    }
    if (!parseUrl(url, opts.host, opts.port, opts.path)) {
        std::fprintf(stderr, "[bcurl] cannot parse URL: %s\n", url.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------
// Resolve host and connect a single TCP socket. Returns the fd, or -1.
// Tries every address getaddrinfo returns (so "localhost" can fall back from
// ::1 to 127.0.0.1).
//
int connectTo(const std::string& host, uint16_t port) {
    char port_str[6];
    std::snprintf(port_str, sizeof(port_str), "%u", port);

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;      // let the resolver pick v4 or v6
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    int gai = ::getaddrinfo(host.c_str(), port_str, &hints, &res);
    if (gai != 0) {
        std::fprintf(stderr, "[bcurl] cannot resolve %s: %s\n",
                     host.c_str(), ::gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;  // success
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);

    if (fd < 0)
        std::fprintf(stderr, "[bcurl] cannot connect to %s:%u\n",
                     host.c_str(), port);
    return fd;
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------
// Build the HEADERS payload: Method=GET, Path, Host.
//
std::vector<uint8_t> buildRequestHeaders(const Options& opts) {
    std::vector<uint8_t> block;
    appendHeader(block, "Method", "GET");
    appendHeader(block, "Path", opts.path);
    appendHeader(block, "Host", opts.host);
    return block;
}

// ---------------------------------------------------------------------------
// Hexdump (verbose only)
// ---------------------------------------------------------------------------
// Classic `hexdump -C` layout: offset, 16 hex bytes, ASCII gutter. Everything
// goes to stderr so stdout stays reserved for the response body.
//
void hexdump(const uint8_t* data, std::size_t len) {
    for (std::size_t off = 0; off < len; off += 16) {
        std::fprintf(stderr, "%08zx  ", off);
        for (std::size_t i = 0; i < 16; ++i) {
            if (off + i < len)
                std::fprintf(stderr, "%02x ", data[off + i]);
            else
                std::fprintf(stderr, "   ");
            if (i == 7) std::fputc(' ', stderr);
        }
        std::fputc('|', stderr);
        for (std::size_t i = 0; i < 16 && off + i < len; ++i) {
            uint8_t c = data[off + i];
            std::fputc((c >= 0x20 && c < 0x7f) ? c : '.', stderr);
        }
        std::fprintf(stderr, "|\n");
    }
}

// Re-serialize a parsed frame back to its on-wire bytes (header + payload) and
// dump it, preceded by a one-line human summary.
void dumpFrame(const char* direction, const FrameHeader& h,
               const std::vector<uint8_t>& payload) {
    std::fprintf(stderr, "%s type=0x%02x flags=0x%02x stream=%u len=%u\n",
                 direction, h.frame_type, h.flags, h.stream_id,
                 h.payload_length);
    std::vector<uint8_t> raw(8 + payload.size());
    serializeFrameHeader(h, raw.data());
    if (!payload.empty())
        std::memcpy(raw.data() + 8, payload.data(), payload.size());
    hexdump(raw.data(), raw.size());
}

// ---------------------------------------------------------------------------
// Response reading
// ---------------------------------------------------------------------------
// Stream frames until END_STREAM (or EOF/error):
//   * verbose: dump every frame, and print decoded response headers
//   * DATA payloads are written to stdout as they arrive
// Returns the HTTP-like status code, or -1 on I/O error / missing response /
// peer reset.
//
int readResponse(int fd, bool verbose) {
    int  status      = -1;
    bool got_headers = false;
    bool peer_reset  = false;

    while (true) {
        FrameHeader h;
        std::vector<uint8_t> payload;
        std::string err;

        FrameStatus st = readFrame(fd, h, payload, MAX_PAYLOAD_LENGTH, &err);
        if (st == FrameStatus::CleanEof) break;
        if (st == FrameStatus::Error) {
            std::fprintf(stderr, "[bcurl] read error: %s\n", err.c_str());
            return -1;
        }

        if (verbose) dumpFrame("<<<", h, payload);

        // Unknown frame types are skipped using their declared length; they do
        // not affect the current response.
        if (!isKnownFrameType(h.frame_type)) continue;

        switch (h.frame_type) {
            case FRAME_HEADERS: {
                std::vector<Header> parsed;
                if (!parseHeaderBlock(payload.data(), payload.size(), parsed)) {
                    std::fprintf(stderr, "[bcurl] malformed response headers\n");
                    return -1;
                }
                got_headers = true;
                for (const auto& kv : parsed) {
                    if (verbose)
                        std::fprintf(stderr, "        %s: %s\n",
                                     kv.name.c_str(), kv.value.c_str());
                    if (kv.name == "Status")
                        status = std::atoi(kv.value.c_str());
                }
                break;
            }
            case FRAME_DATA:
                if (!payload.empty())
                    std::fwrite(payload.data(), 1, payload.size(), stdout);
                break;
            case FRAME_RST:
                peer_reset = true;
                break;
            default:
                break;
        }

        if (h.flags & FLAG_END_STREAM) break;
    }

    std::fflush(stdout);

    if (peer_reset) return -1;
    if (!got_headers || status < 0) return -1;
    return status;
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    Options opts;
    if (!parseArgs(argc, argv, opts)) return 2;

    if (opts.verbose)
        std::fprintf(stderr, "[bcurl] GET %s:%u%s\n",
                     opts.host.c_str(), opts.port, opts.path.c_str());

    // ONE connection for the whole exchange.
    int fd = connectTo(opts.host, opts.port);
    if (fd < 0) return 1;

    // Build and send the request as a single HEADERS frame that ends the stream.
    std::vector<uint8_t> headers = buildRequestHeaders(opts);
    if (opts.verbose) {
        FrameHeader req;
        req.payload_length = static_cast<uint32_t>(headers.size());
        req.frame_type     = FRAME_HEADERS;
        req.flags          = FLAG_END_STREAM;
        req.stream_id      = 0;
        dumpFrame(">>>", req, headers);
    }
    if (!writeFrameVec(fd, FRAME_HEADERS, FLAG_END_STREAM, 0, headers)) {
        std::fprintf(stderr, "[bcurl] failed to send request\n");
        ::close(fd);
        return 1;
    }

    int status = readResponse(fd, opts.verbose);
    ::close(fd);

    // Exit code: 0 for < 400, non-zero for 4xx/5xx, missing response, or I/O
    // error. (2 is reserved for command-line / URL parse failures.)
    if (status < 0) {
        std::fprintf(stderr, "[bcurl] no valid response\n");
        return 1;
    }
    if (status >= 400)
        return 1;
    return 0;
}
