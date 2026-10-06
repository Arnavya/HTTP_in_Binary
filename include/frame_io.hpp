// frame_io.hpp
//
// Socket-level framing shared by bserve and bcurl.
//
// Everything here works on a raw connected TCP file descriptor. There is NO
// connection management (open/close) - callers own the fd. This is what lets
// both programs hold a single connection open for many frames.
//
// All functions:
//   * loop over short reads/writes
//   * retry on EINTR
//   * never throw
//
#ifndef BITMID_FRAME_IO_HPP
#define BITMID_FRAME_IO_HPP

#include "protocol.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>

namespace bitmid {

// ---------------------------------------------------------------------------
// Raw read/write helpers
// ---------------------------------------------------------------------------
// Return true on a full transfer. `out_eof` (optional) is set true when the
// peer closed cleanly before any bytes of this transfer arrived.
//
inline bool recvAll(int fd, void* buf, std::size_t n, bool* out_eof = nullptr) {
    auto* p = static_cast<uint8_t*>(buf);
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd, p + got, n - got, 0);
        if (r == 0) {
            if (out_eof) *out_eof = (got == 0);
            return false;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            if (out_eof) *out_eof = false;
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    return true;
}

inline bool sendAll(int fd, const void* buf, std::size_t n) {
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
// Frame read
// ---------------------------------------------------------------------------
enum class FrameStatus {
    Ok,         // a full frame was read into h/payload
    CleanEof,   // peer closed between frames (normal end of connection)
    Error       // short/failed read, or payload_length above the cap
};

// Read exactly one frame.
//
// The payload is always read in full (up to `max_payload`) regardless of the
// frame type. That is deliberate: an unknown frame type is "skipped" simply by
// reading and discarding its payload, so the stream stays in sync.
//
// On FrameStatus::Error we do NOT attempt to resync - the byte stream can no
// longer be trusted - so callers should send any final error they want and
// close. `err` (optional) receives a human-readable reason.
//
inline FrameStatus readFrame(int fd, FrameHeader& h, std::vector<uint8_t>& payload,
                             uint32_t max_payload = MAX_PAYLOAD_LENGTH,
                             std::string* err = nullptr) {
    uint8_t header_bytes[8];
    bool eof = false;
    if (!recvAll(fd, header_bytes, sizeof(header_bytes), &eof)) {
        if (eof) return FrameStatus::CleanEof;
        if (err) *err = "I/O error while reading frame header";
        return FrameStatus::Error;
    }

    h = parseFrameHeader(header_bytes);

    if (h.payload_length > max_payload) {
        if (err) *err = "declared payload length exceeds limit";
        return FrameStatus::Error;
    }

    payload.resize(h.payload_length);
    if (h.payload_length != 0) {
        if (!recvAll(fd, payload.data(), payload.size(), &eof)) {
            if (err) *err = eof ? "peer closed mid-payload"
                                : "I/O error while reading frame payload";
            return FrameStatus::Error;
        }
    }
    return FrameStatus::Ok;
}

// ---------------------------------------------------------------------------
// Frame write
// ---------------------------------------------------------------------------
// Serialize and send exactly one frame (header + payload). `payload` may be
// null when `payload_len` is 0.
//
inline bool writeFrame(int fd, uint8_t frame_type, uint8_t flags,
                       uint16_t stream_id, const void* payload,
                       uint32_t payload_len) {
    FrameHeader h;
    h.payload_length = payload_len;
    h.frame_type     = frame_type;
    h.flags          = flags;
    h.stream_id      = stream_id;

    uint8_t header_bytes[8];
    serializeFrameHeader(h, header_bytes);

    if (!sendAll(fd, header_bytes, sizeof(header_bytes))) return false;
    if (payload_len != 0 && !sendAll(fd, payload, payload_len)) return false;
    return true;
}

inline bool writeFrameVec(int fd, uint8_t frame_type, uint8_t flags,
                          uint16_t stream_id, const std::vector<uint8_t>& payload) {
    return writeFrame(fd, frame_type, flags, stream_id,
                      payload.empty() ? nullptr : payload.data(),
                      static_cast<uint32_t>(payload.size()));
}

} // namespace bitmid

#endif // BITMID_FRAME_IO_HPP
