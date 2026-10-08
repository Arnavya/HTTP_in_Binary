# Annotated Hexdump — One Complete Request/Response Cycle

Captured with `./bcurl -v localhost:9000/hello.txt` against `./bserve ./www 9000`.
The file `www/hello.txt` contains `hello world\n` (12 bytes). Frames sent by the
client are marked `>>>`, frames received by the client `<<<`. All multi-byte
integers are big-endian.

---

## 1. Client → Server: request (`>>>`, 8 + 31 = 39 bytes)

```
00000000  00 00 00 1f 01 01 00 00  01 00 03 47 45 54 02 00 |...........GET..|
00000010  0a 2f 68 65 6c 6c 6f 2e  74 78 74 03 00 09 6c 6f |./hello.txt...lo|
00000020  63 61 6c 68 6f 73 74                             |calhost|
```

**Frame header (8 bytes):**

| Bytes | Hex             | Meaning                                          |
|-------|-----------------|--------------------------------------------------|
| 0–3   | `00 00 00 1f`   | `payload_length = 31`                            |
| 4     | `01`            | `frame_type = 0x01` HEADERS                       |
| 5     | `01`            | `flags = 0x01` END_STREAM (request has no body)   |
| 6–7   | `00 00`         | `stream_id = 0` (reserved)                        |

**HEADERS payload (31 bytes), entry by entry:**

| Bytes | Hex                                          | Decoded                                     |
|-------|----------------------------------------------|---------------------------------------------|
| 8–13  | `01 00 03 47 45 54`                          | id `0x01` Method, len 3, `"GET"`            |
| 14–25 | `02 00 0a 2f 68 65 6c 6c 6f 2e 74 78 74`     | id `0x02` Path, len 10, `"/hello.txt"`      |
| 26–38 | `03 00 09 6c 6f 63 61 6c 68 6f 73 74`        | id `0x03` Host, len 9, `"localhost"`        |

Each entry is `[1B id][2B big-endian length][value]`. Known names cost one
byte; a custom header would use the `0x00` escape plus a length-prefixed name.

---

## 2. Server → Client: response headers (`<<<`, 8 + 24 = 32 bytes)

```
00000000  00 00 00 18 01 00 00 00  04 00 03 32 30 30 05 00 |...........200..|
00000010  0a 74 65 78 74 2f 70 6c  61 69 6e 06 00 02 31 32 |.text/plain...12|
```

**Frame header (8 bytes):**

| Bytes | Hex           | Meaning                                        |
|-------|---------------|------------------------------------------------|
| 0–3   | `00 00 00 18` | `payload_length = 24`                          |
| 4     | `01`          | `frame_type = 0x01` HEADERS                     |
| 5     | `00`          | `flags = 0x00` END_STREAM **not** set — a DATA frame follows |
| 6–7   | `00 00`       | `stream_id = 0`                                 |

**HEADERS payload (24 bytes):**

| Bytes | Hex                                        | Decoded                                        |
|-------|--------------------------------------------|------------------------------------------------|
| 8–13  | `04 00 03 32 30 30`                        | id `0x04` Status, len 3, `"200"`               |
| 14–25 | `05 00 0a 74 65 78 74 2f 70 6c 61 69 6e`   | id `0x05` Content-Type, len 10, `"text/plain"` |
| 26–31 | `06 00 02 31 32`                           | id `0x06` Content-Length, len 2, `"12"`        |

---

## 3. Server → Client: response body (`<<<`, 8 + 12 = 20 bytes)

```
00000000  00 00 00 0c 02 01 00 00  68 65 6c 6c 6f 20 77 6f |........hello wo|
00000010  72 6c 64 0a                                      |rld.|
```

| Bytes | Hex                            | Meaning                                        |
|-------|--------------------------------|------------------------------------------------|
| 0–3   | `00 00 00 0c`                  | `payload_length = 12`                          |
| 4     | `02`                           | `frame_type = 0x02` DATA                        |
| 5     | `01`                           | `flags = 0x01` END_STREAM — last frame of response |
| 6–7   | `00 00`                        | `stream_id = 0`                                 |
| 8–19  | `68 65 6c 6c 6f 20 77 6f 72 6c 64 0a` | payload `"hello world\n"`             |

The client writes bytes 8–19 verbatim to stdout. A body larger than 64 KiB is
split across multiple DATA frames; only the final one sets `END_STREAM`.

---

## 4. Cycle summary

```
>>>  HEADERS  END_STREAM   Method/Path/Host          (39 bytes)
<<<  HEADERS               Status/Content-Type/Length (32 bytes)
<<<  DATA     END_STREAM   "hello world\n"           (20 bytes)
```

Total on the wire: 91 bytes. The connection remains open; the client may
immediately send another request, and any unknown frame type received would be
skipped using its `payload_length` without disturbing the stream.
