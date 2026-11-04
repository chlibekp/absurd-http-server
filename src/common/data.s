// Shared read-only data: response templates, header names, MIME types,
// static responses laid out as table entries. Architecture independent
// (only .ascii/.byte/.short/.long/.quad).

        .section .rodata
        .p2align 4
s_d0:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n"
s_d0_end:
s_d1:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n"
s_d1_end:
s_d2:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: keep-alive\r\n\r\n"
s_d2_end:
        .if (s_d0_end - s_d0) != D0_LEN || (s_d1_end - s_d1) != D1_LEN || (s_d2_end - s_d2) != D2_LEN
        .error "Date line length mismatch"
        .endif

        .macro STR name, text
\name:  .ascii  "\text"
\name\()_end:
        .endm

        // a file's head: s_h200 <len> s_tail1 <type> s_etag1 <tag> s_lm <date> s_tail2
        STR s_h200,     "HTTP/1.1 200 OK\r\nContent-Length: "
        STR s_tail1,    "\r\nServer: absurd\r\nContent-Type: "
        STR s_etag1,    "\r\nETag: \""
        STR s_lm,       "\"\r\nLast-Modified: "
        STR s_tail2,    "\r\nAccept-Ranges: bytes\r\nX-Content-Type-Options: nosniff\r\n"
        STR s_h304,     "HTTP/1.1 304 Not Modified\r\nServer: absurd\r\nETag: \""
        STR s_q_crlf,   "\"\r\n"
        STR s_loc1,     "HTTP/1.1 301 Moved Permanently\r\nServer: absurd\r\nContent-Length: 0\r\nLocation: "
        STR s_loc2,     "/\r\nX-Content-Type-Options: nosniff\r\n"
        STR s_206a,     "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes "
        STR s_206b,     "\r\nContent-Length: "
        STR s_416a,     "HTTP/1.1 416 Range Not Satisfiable\r\nServer: absurd\r\nContent-Length: 0\r\nX-Content-Type-Options: nosniff\r\nContent-Range: bytes */"
        STR s_crlf,     "\r\n"
        STR s_307a,     "HTTP/1.1 307 Temporary Redirect\r\nServer: absurd\r\nCache-Control: no-store\r\nContent-Length: 0\r\nSet-Cookie: absurd_pow=; Path=/; Max-Age=0\r\nSet-Cookie: absurd_clearance="
        STR s_307b,     "; Path=/; Max-Age="
        STR s_307c,     "; HttpOnly; SameSite=Lax\r\nLocation: "
        STR s_chh,      "HTTP/1.1 403 Forbidden\r\nServer: absurd\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Length: "
        STR s_octet,    "application/octet-stream"

        // proxy
        STR s_v11,      " HTTP/1.1\r\n"
        STR s_v11s,     "HTTP/1.1"
        STR s_upclose,  "Connection: close\r\nVia: 1.1 absurd\r\nX-Forwarded-For: "
        STR s_upte,     "Transfer-Encoding: chunked\r\n"
        STR s_uphost,   "Host: "
        STR s_cclose,   "Connection: close\r\n"
        STR s_cka,      "Connection: keep-alive\r\n"

s_index:    .ascii "index.html"
s_hex:      .ascii "0123456789abcdef"
s_dot:      .asciz "."
s_days:     .ascii "SunMonTueWedThuFriSat"
s_months:   .ascii "JanFebMarAprMayJunJulAugSepOctNovDec"

        // lowercase header names, compared case-insensitively
s_host:     .ascii "host"
s_connection: .ascii "connection"
s_close:    .ascii "close"
s_keepalive: .ascii "keep-alive"
s_cl:       .ascii "content-length"
s_te:       .ascii "transfer-encoding"
s_chunked:  .ascii "chunked"
s_expect:   .ascii "expect"
s_100c:     .ascii "100-continue"
s_inm:      .ascii "if-none-match"
s_im:       .ascii "if-match"
s_ims:      .ascii "if-modified-since"
s_ius:      .ascii "if-unmodified-since"
s_ir:       .ascii "if-range"
s_range:    .ascii "range"
s_bytes:    .ascii "bytes"
s_cookie:   .ascii "cookie"
s_pconn:    .ascii "proxy-connection"
s_tehdr:    .ascii "te"
s_upgrade:  .ascii "upgrade"
s_xff:      .ascii "x-forwarded-for"
s_trailer:  .ascii "trailer"
s_http:     .ascii "http://"
s_https:    .ascii "https://"
        // cookie names are case-sensitive
s_ck_clr:   .ascii "absurd_clearance"
s_ck_pow:   .ascii "absurd_pow"

        // method names, length-prefixed, in MT_* order from 1
t_methods:
        .byte 3
        .ascii "GET"
        .byte 4
        .ascii "HEAD"
        .byte 7
        .ascii "OPTIONS"
        .byte 4
        .ascii "POST"
        .byte 3
        .ascii "PUT"
        .byte 6
        .ascii "DELETE"
        .byte 5
        .ascii "PATCH"
        .byte 5
        .ascii "TRACE"
        .byte 7
        .ascii "CONNECT"
        .byte 0

        .macro MIME ext, type
        .byte   9f - 8f
8:      .ascii  "\ext"
9:      .byte   7f - 6f
6:      .ascii  "\type"
7:
        .endm
t_mime:
        MIME    "html",  "text/html; charset=utf-8"
        MIME    "htm",   "text/html; charset=utf-8"
        MIME    "css",   "text/css; charset=utf-8"
        MIME    "js",    "text/javascript; charset=utf-8"
        MIME    "mjs",   "text/javascript; charset=utf-8"
        MIME    "json",  "application/json"
        MIME    "map",   "application/json"
        MIME    "webmanifest", "application/manifest+json"
        MIME    "txt",   "text/plain; charset=utf-8"
        MIME    "md",    "text/markdown; charset=utf-8"
        MIME    "csv",   "text/csv; charset=utf-8"
        MIME    "xml",   "application/xml"
        MIME    "svg",   "image/svg+xml"
        MIME    "png",   "image/png"
        MIME    "jpg",   "image/jpeg"
        MIME    "jpeg",  "image/jpeg"
        MIME    "gif",   "image/gif"
        MIME    "webp",  "image/webp"
        MIME    "avif",  "image/avif"
        MIME    "ico",   "image/x-icon"
        MIME    "bmp",   "image/bmp"
        MIME    "wasm",  "application/wasm"
        MIME    "pdf",   "application/pdf"
        MIME    "woff",  "font/woff"
        MIME    "woff2", "font/woff2"
        MIME    "ttf",   "font/ttf"
        MIME    "otf",   "font/otf"
        MIME    "mp4",   "video/mp4"
        MIME    "webm",  "video/webm"
        MIME    "mp3",   "audio/mpeg"
        MIME    "ogg",   "audio/ogg"
        MIME    "wav",   "audio/wav"
        MIME    "zip",   "application/zip"
        MIME    "gz",    "application/gzip"
        .byte   0

// Static responses. \len is the decimal length of "<status>\n", checked below.
        .macro ERRRESP name, status, len, extra=""
h_\name:
        .ascii  "HTTP/1.1 \status\r\nServer: absurd\r\nContent-Type: text/plain; charset=utf-8\r\n\extra"
        .ascii  "Content-Length: \len\r\nX-Content-Type-Options: nosniff\r\n"
h_\name\()_end:
b_\name:
        .ascii  "\status\n"
b_\name\()_end:
        .if (b_\name\()_end - b_\name) != \len
        .error "error body length mismatch"
        .endif
        .endm

        ERRRESP 400, "400 Bad Request", 16
        ERRRESP 404, "404 Not Found", 14
        ERRRESP 405, "405 Method Not Allowed", 23, "Allow: GET, HEAD, OPTIONS\r\n"
        ERRRESP 412, "412 Precondition Failed", 24
        ERRRESP 413, "413 Content Too Large", 22
        ERRRESP 414, "414 URI Too Long", 17
        ERRRESP 417, "417 Expectation Failed", 23
        ERRRESP 431, "431 Request Header Fields Too Large", 36
        ERRRESP 501, "501 Not Implemented", 20
        ERRRESP 502, "502 Bad Gateway", 16
        ERRRESP 503, "503 Service Unavailable", 24
        ERRRESP 504, "504 Gateway Timeout", 20
        ERRRESP 505, "505 HTTP Version Not Supported", 31
h_options:
        .ascii  "HTTP/1.1 204 No Content\r\nServer: absurd\r\nAllow: GET, HEAD, OPTIONS\r\nX-Content-Type-Options: nosniff\r\n"
h_options_end:
h_continue:
        .ascii  "HTTP/1.1 100 Continue\r\n\r\n"
h_continue_end:

        .macro ENTRY name, flags, hdr, hdrend, body, bodyend
        .p2align 4
e_\name:
        .quad   0, 0
        .long   0, \flags
        .quad   \hdr
        .long   \hdrend - \hdr, 0
        .quad   0
        .quad   \body
        .quad   \bodyend - \body
        .quad   0, 0, 0, 0, 0, 0, 0, 0
        .endm
        .macro ERRENT name, flags
        ENTRY   \name, \flags, h_\name, h_\name\()_end, b_\name, b_\name\()_end
        .endm

        ERRENT  400, EF_CLOSE
        ERRENT  404, 0
        ERRENT  405, 0
        ERRENT  412, 0
        ERRENT  413, EF_CLOSE
        ERRENT  414, EF_CLOSE
        ERRENT  417, EF_CLOSE
        ERRENT  431, EF_CLOSE
        ERRENT  501, EF_CLOSE
        ERRENT  502, EF_CLOSE
        ERRENT  503, EF_CLOSE
        ERRENT  504, EF_CLOSE
        ERRENT  505, EF_CLOSE
        ENTRY   options, 0, h_options, h_options_end, h_options, h_options
        ENTRY   continue, EF_RAW, h_continue, h_continue_end, h_continue, h_continue

        // SHA-256
        .p2align 4
t_sha_k:
        .long   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
        .long   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
        .long   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
        .long   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
        .long   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
        .long   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
        .long   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
        .long   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
t_sha_h:
        .long   0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

// ---------------------------------------------------------------- messages
        STR s_b1,   "absurd: serving "
        STR s_b2,   " files ("
        STR s_b3,   " bytes) from "
        STR s_b4,   " on "
        STR s_b5,   ", "
        STR s_b6,   " threads, io_uring + seccomp sandbox"
        STR s_b7,   ", cpu-steered"
        STR s_b8,   ", running as nobody"
        STR s_b9,   "\nabsurd: warning: skipped "
        STR s_b10,  " files (1 GiB snapshot cap or table full)"
        STR s_b11,  "\nabsurd: proxy "
        STR s_b12,  " -> "
        STR s_b13,  "\nabsurd: JS challenge on "
        STR s_b14,  " (difficulty "
        STR s_b15,  " bits)"
        STR s_usage, "usage: absurd [-c config] [-p port] [-t threads] [document-root]\n"
        STR s_fatal, "absurd: fatal: "
        STR s_errno, " failed (errno "
        STR s_cfgerr, "absurd: config line "
        STR s_colon, ": "
m_socket:   .asciz "socket"
m_bind:     .asciz "bind"
m_listen:   .asciz "listen"
m_mmap:     .asciz "mmap"
m_mprotect: .asciz "mprotect"
m_clone:    .asciz "clone"
m_priv:     .asciz "dropping privileges"
m_root:     .asciz "opening the document root"
m_cfgopen:  .asciz "opening the config file"
m_setup:    .asciz "io_uring_setup (need Linux >= 6.6 and io_uring allowed by seccomp)"
m_files:    .asciz "register fixed files"
m_restrict: .asciz "restricting io_uring"
m_seccomp:  .asciz "installing seccomp filter"
c_unknown:  .asciz "unknown directive"
c_args:     .asciz "wrong number of arguments"
c_number:   .asciz "bad number"
c_addr:     .asciz "bad address (want IPv4:port)"
c_prefix:   .asciz "prefix must start with /"
c_toomany:  .asciz "too many entries"
c_big:      .asciz "file too large"

// config directives, length-prefixed, in CD_* order from 1
t_directives:
        .byte 6
        .ascii "listen"
        .byte 7
        .ascii "threads"
        .byte 4
        .ascii "root"
        .byte 5
        .ascii "proxy"
        .byte 9
        .ascii "challenge"
        .byte 20
        .ascii "challenge_difficulty"
        .byte 13
        .ascii "challenge_ttl"
        .byte 14
        .ascii "header_timeout"
        .byte 12
        .ascii "idle_timeout"
        .byte 12
        .ascii "send_timeout"
        .byte 16
        .ascii "upstream_timeout"
        .byte 0
