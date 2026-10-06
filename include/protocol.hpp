// protocol.hpp
//
// "Bit in the Middle" - a custom binary HTTP protocol.
//
// This header is shared by both programs:
//   * bserve  (server)  - ./bserve ./www 9000
//   * bcurl   (client)  - ./bcurl -v localhost:9000/index.html
//
// Everything on the wire is BIG-ENDIAN (network byte order). The single
// exception is the application-level header values, which are length-prefixed
// raw bytes and therefore byte-order independent.
//
// Wire format, in order:
//
//   +-----------------------------------------------------+
//   | 8-byte fixed Frame Header                           |
//   +-----------------------------------------------------+
//   | payload_length bytes of payload                     |
//   +-----------------------------------------------------+
//
// The payload interpretation depends on the frame type (see below).
//
#ifndef BITMID_PROTOCOL_HPP
#define BITMID_PROTOCOL_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

#include <arpa/inet.h>   // htonl/ntohl/htons/ntohs (Portable across POSIX)

namespace bitmid {

// ---------------------------------------------------------------------------
// 1. Fixed-size frame header (8 bytes)
// ---------------------------------------------------------------------------
//
//   offset  size  field
//   ------  ----  -------------------------------------------------
//   0       4     payload_length : uint32_t, network byte order
//   4       1     frame_type     : uint8_t
//   5       1     flags          : uint8_t
//   6       2     stream_id      : uint16_t, network byte order
//
// We keep an in-memory struct for convenient passing around, but the
// authoritative serialization/deserialization happens byte-by-byte in the
// two helpers below. That avoids all struct-packing / padding surprises.
//
struct FrameHeader {
    uint32_t payload_length;  // bytes that follow this header
    uint8_t  frame_type;      // see FrameType
    uint8_t  flags;           // see Flags
    uint16_t stream_id;       // 0 unless multiplexing is used
};

// A compiled-in guarantee that our mental model matches the compiler's.
static_assert(sizeof(FrameHeader) == 8,
              "FrameHeader must be exactly 8 bytes on the wire");

// ---------------------------------------------------------------------------
// 2. Frame types
// ---------------------------------------------------------------------------
// 0x01 HEADERS : carries a block of serialized request/response headers.
// 0x02 DATA    : carries opaque body bytes.
// 0x03 RST     : aborts the current exchange (error/teardown).
//
// Any type not listed here is "unknown". A conforming receiver MUST read
// payload_length and skip exactly that many bytes instead of failing.
//
enum FrameType : uint8_t {
    FRAME_HEADERS = 0x01,
    FRAME_DATA    = 0x02,
    FRAME_RST     = 0x03
};

// ---------------------------------------------------------------------------
// 3. Frame flags
// ---------------------------------------------------------------------------
// END_STREAM (0x01) marks the final frame of a request or response.
// Multiple flags could be OR-ed together in the future; today only one bit
// is defined.
//
enum FrameFlags : uint8_t {
    FLAG_NONE       = 0x00,
    FLAG_END_STREAM = 0x01
};

// ---------------------------------------------------------------------------
// 4. Header serialization
// ---------------------------------------------------------------------------
// A HEADERS payload is a sequence of length-prefixed key/value pairs. Common
// keys are compressed to a single-byte "header id" to save space; anything
// else uses the EXTENDED escape (0x00) followed by a length-prefixed name.
//
// Each entry on the wire:
//
//   [1 byte  header_id][2 bytes  value_length (BE)][value_length bytes value]
//
// For HEADER_EXTENDED the name is inserted before the value:
//
//   [1 byte 0x00][2 bytes name_length (BE)][name][2 bytes value_length (BE)][value]
//
// value_length is capped at 65535 because it is a 16-bit field; larger values
// must be split across DATA frames instead.
//
enum HeaderId : uint8_t {
    HEADER_EXTENDED = 0x00,  // escape: name follows as length-prefixed string
    HEADER_METHOD   = 0x01,
    HEADER_PATH     = 0x02,
    HEADER_HOST     = 0x03,
    HEADER_STATUS   = 0x04,
    HEADER_CONTENT_TYPE       = 0x05,
    HEADER_CONTENT_LENGTH     = 0x06,
    HEADER_CONTENT_ENCODING   = 0x07
};

// Reverse lookup for well-known ids. Returns nullptr for unknown/extended.
inline const char* headerIdName(HeaderId id) {
    switch (id) {
        case HEADER_METHOD:         return "Method";
        case HEADER_PATH:           return "Path";
        case HEADER_HOST:           return "Host";
        case HEADER_STATUS:         return "Status";
        case HEADER_CONTENT_TYPE:   return "Content-Type";
        case HEADER_CONTENT_LENGTH: return "Content-Length";
        case HEADER_CONTENT_ENCODING: return "Content-Encoding";
        default:                    return nullptr;
    }
}

// Convenience: does a known name map to a single-byte id?
inline uint8_t headerIdForName(const std::string& name) {
    if (name == "Method")         return HEADER_METHOD;
    if (name == "Path")           return HEADER_PATH;
    if (name == "Host")           return HEADER_HOST;
    if (name == "Status")         return HEADER_STATUS;
    if (name == "Content-Type")   return HEADER_CONTENT_TYPE;
    if (name == "Content-Length") return HEADER_CONTENT_LENGTH;
    if (name == "Content-Encoding") return HEADER_CONTENT_ENCODING;
    return HEADER_EXTENDED;
}

// ---------------------------------------------------------------------------
// 5. Endianness helpers (host <-> network)
// ---------------------------------------------------------------------------
// On little-endian hosts these are byte swaps; on big-endian they are no-ops.
// We use the POSIX htonX/ntohX family, which is correct on both.
//
inline uint32_t hostToNet32(uint32_t v) { return htonl(v); }
inline uint32_t netToHost32(uint32_t v) { return ntohl(v); }
inline uint16_t hostToNet16(uint16_t v) { return htons(v); }
inline uint16_t netToHost16(uint16_t v) { return ntohs(v); }

// ---------------------------------------------------------------------------
// 6. Byte-level (de)serialization of the fixed header
// ---------------------------------------------------------------------------
// These are the ONLY places that touch the wire representation of a header.
//
// serializeFrameHeader(): writes exactly 8 bytes into out[0..7].
// parseFrameHeader():     reads exactly 8 bytes from in[0..7].
//
inline void serializeFrameHeader(const FrameHeader& h, uint8_t out[8]) {
    uint32_t len = hostToNet32(h.payload_length);
    uint16_t sid = hostToNet16(h.stream_id);

    std::memcpy(out + 0, &len, 4);   // payload length, big-endian
    out[4] = h.frame_type;           // frame type
    out[5] = h.flags;                // flags
    std::memcpy(out + 6, &sid, 2);   // stream id, big-endian
}

inline FrameHeader parseFrameHeader(const uint8_t in[8]) {
    FrameHeader h;
    uint32_t len;
    uint16_t sid;

    std::memcpy(&len, in + 0, 4);
    std::memcpy(&sid, in + 6, 2);

    h.payload_length = netToHost32(len);
    h.frame_type     = in[4];
    h.flags          = in[5];
    h.stream_id      = netToHost16(sid);
    return h;
}

// Upper bound on a single payload. Guards against absurd lengths from a
// malicious or corrupt peer turning into a huge allocation.
//
// 16 MiB comfortably covers headers plus the biggest file chunk we emit.
//
constexpr uint32_t MAX_PAYLOAD_LENGTH = 16u * 1024u * 1024u;

// True for a type our implementation knows how to interpret. Unknown types
// must still be consumed and skipped using payload_length.
inline bool isKnownFrameType(uint8_t t) {
    return t == FRAME_HEADERS || t == FRAME_DATA || t == FRAME_RST;
}

// ---------------------------------------------------------------------------
// 7. Header block (de)serialization
// ---------------------------------------------------------------------------
// A decoded header, name/value kept as text regardless of how it was framed.
//
struct Header {
    std::string name;
    std::string value;
};

// Big-endian 16-bit append/read on a byte buffer.
inline void appendU16BE(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

// Reads a big-endian uint16 at data[off], advancing off. False if it would
// read past the end.
inline bool readU16BE(const uint8_t* data, std::size_t len,
                      std::size_t& off, uint16_t& out) {
    if (off + 2 > len) return false;
    out = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
    off += 2;
    return true;
}

// Append one name/value pair to a HEADERS payload, applying the well-known
// id compression where possible (see HeaderId). Throws std::length_error if a
// name or value exceeds the 16-bit length field.
inline void appendHeader(std::vector<uint8_t>& out,
                         const std::string& name, const std::string& value) {
    if (value.size() > 0xffff)
        throw std::length_error("header value exceeds 65535 bytes");

    uint8_t id = headerIdForName(name);
    out.push_back(id);
    if (id == HEADER_EXTENDED) {
        if (name.size() > 0xffff)
            throw std::length_error("header name exceeds 65535 bytes");
        appendU16BE(out, static_cast<uint16_t>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
    }
    appendU16BE(out, static_cast<uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

// Parse a complete HEADERS payload into name/value pairs.
//
// Returns false if the block is malformed: truncated length prefix, a value
// that runs past the end, or a single-byte id that is neither EXTENDED nor a
// known HeaderId. On false the contents of `out` are undefined.
//
inline bool parseHeaderBlock(const uint8_t* data, std::size_t len,
                             std::vector<Header>& out) {
    std::size_t off = 0;
    while (off < len) {
        uint8_t id = data[off++];
        std::string name;

        if (id == HEADER_EXTENDED) {
            uint16_t nlen = 0;
            if (!readU16BE(data, len, off, nlen)) return false;
            if (off + nlen > len) return false;
            name.assign(reinterpret_cast<const char*>(data + off), nlen);
            off += nlen;
        } else {
            const char* known = headerIdName(static_cast<HeaderId>(id));
            if (known == nullptr) return false;   // unknown compressed id
            name = known;
        }

        uint16_t vlen = 0;
        if (!readU16BE(data, len, off, vlen)) return false;
        if (off + vlen > len) return false;
        std::string value(reinterpret_cast<const char*>(data + off), vlen);
        off += vlen;

        out.push_back(Header{std::move(name), std::move(value)});
    }
    return true;
}

} // namespace bitmid

#endif // BITMID_PROTOCOL_HPP
