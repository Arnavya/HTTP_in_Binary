# Bit-in-the-Middle (BitM) — Binary HTTP Protocol Specification

**Version 1.0 · Track 1 `bserve` / Track 2 `bcurl`**

BitM is a minimal, binary, connection-oriented request/response protocol in the
spirit of HTTP/2. A client sends one framed request over a persistent TCP
connection; the server answers with one framed response and keeps the
connection open for further requests. All multi-byte integers are unsigned and
**big-endian (network byte order)**.

---

## 1. Transport

* TCP. Default port **9000**.
* A connection carries an unbounded sequence of independent request/response
  cycles. It is closed by either peer or after an unrecoverable protocol error.
* A cycle is: client `HEADERS` (…optional `DATA`) → server `HEADERS` (+`DATA`),
  each sequence terminated by the `END_STREAM` flag.

## 2. Frame format

Every frame is an **8-byte fixed header** followed by `payload_length` bytes of
payload.

| Offset | Size | Field            | Type     | Description                                  |
|-------:|-----:|------------------|----------|----------------------------------------------|
| 0      | 4    | `payload_length` | uint32   | Payload bytes that follow (big-endian)       |
| 4      | 1    | `frame_type`     | uint8    | See §3                                       |
| 5      | 1    | `flags`          | uint8    | See §4                                       |
| 6      | 2    | `stream_id`      | uint16   | Reserved; MUST be `0x0000` in v1 (big-endian)|

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      payload_length (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| frame_type    | flags         |         stream_id            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload (variable)                      |
+-----------------------------------------------------------------+
```

`payload_length` is capped at **16 MiB** by this implementation. A larger value
is a fatal protocol error.

## 3. Frame types

| Value | Name    | Meaning                                             |
|------:|---------|-----------------------------------------------------|
| 0x01  | HEADERS | A block of length-prefixed name/value pairs (§5)    |
| 0x02  | DATA    | Opaque body bytes                                   |
| 0x03  | RST     | Abort the current exchange (error / teardown)       |

**Unknown frame rule (mandatory).** A receiver that encounters an unrecognized
`frame_type` MUST read `payload_length` from the header and **discard exactly
that many bytes**, leaving the stream synchronized. It MUST NOT crash, close
the connection, or misparse subsequent frames.

## 4. Flags

| Value | Name        | Meaning                                    |
|------:|-------------|--------------------------------------------|
| 0x01  | END_STREAM  | Final frame of this request or response     |

`0x00` is the empty flag set. Bits other than `END_STREAM` are reserved and
MUST be `0`; a receiver treats any set reserved bit as a malformed request.

## 5. Header serialization

A `HEADERS` payload is a sequence of entries. Common names are compressed to a
single-byte id; anything else uses the `0x00` escape followed by a
length-prefixed name.

```
 known id:   [1B header_id][2B value_length][value bytes]
 extended :  [1B 0x00][2B name_length][name][2B value_length][value bytes]
```

All length fields are big-endian uint16 (max 65535). Larger values must be sent
as `DATA` instead. Well-known ids:

| Id   | Name             | Id   | Name             |
|-----:|------------------|-----:|------------------|
| 0x00 | (extended escape)| 0x04 | Status           |
| 0x01 | Method           | 0x05 | Content-Type     |
| 0x02 | Path             | 0x06 | Content-Length   |
| 0x03 | Host             | 0x07 | Content-Encoding |

## 6. Requests

A request is a single `HEADERS` frame with `END_STREAM` set (a body is optional
and would arrive as `DATA` frames). Required headers: `Method` (`GET` only in
v1) and `Path` (an absolute path, e.g. `/index.html`). `Host` is informational.

## 7. Responses

A response is a `HEADERS` frame containing `Status`, `Content-Type`, and
`Content-Length`, followed (when the body is non-empty) by one or more `DATA`
frames chunked at 64 KiB; the final frame carries `END_STREAM`. An empty body
places `END_STREAM` on the `HEADERS` frame itself. Status codes:

| Code | Meaning                                             |
|-----:|-----------------------------------------------------|
| 200  | OK — file found and served                          |
| 400  | Bad request — malformed frame/header block          |
| 404  | Not found — missing file or out-of-root path        |
| 405  | Method not allowed — non-GET method                 |
| 500  | Internal error — file could not be read             |

## 8. Server behavior (`bserve <root> <port>`)

Binds `<port>`, accepts one connection at a time, and serves files under
`<root>`. Path `/` maps to `/index.html`; any `..` path component is rejected
(served as 404) so requests cannot escape the root. The connection stays open
across many requests. A fully-consumed malformed frame yields `400` and the
connection continues; an over-long declared length yields `400` and the
connection is closed (the stream cannot be resynchronized).

## 9. Client behavior (`bcurl [-v] host[:port][/path]`)

Opens exactly **one** TCP connection per invocation (no reconnect). Sends a
`GET` request and writes the response body to stdout. `-v` hex-dumps every
frame (sent `>>>` and received `<<<`) to stderr, keeping stdout body-only.
Default port 9000, default path `/`. Exit status: `0` for `< 400`; `1` for
4xx/5xx, missing response, or I/O error; `2` for argument/URL errors.

## 10. Build

```sh
g++ -std=c++17 -Wall -Wextra -Iinclude src/bserve.cpp -o bserve
g++ -std=c++17 -Wall -Wextra -Iinclude src/bcurl.cpp  -o bcurl
# run:
./bserve ./www 9000        # terminal 1
./bcurl -v localhost:9000/index.html   # terminal 2
```
