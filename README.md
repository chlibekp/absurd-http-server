# absurd

absurd is a sandboxed static-file web server and reverse proxy for Linux, written in C. It builds into one static binary for **x86_64 and arm64**. It speaks HTTP/1.1 (RFC 9110/9112) over plain TCP or TLS. Point it at a directory and it serves that directory from memory. It can forward path prefixes to upstream servers, and can make clients solve a JavaScript proof-of-work challenge first.

```sh
make                                   # static build: build/absurd
./build/absurd -p 8080 ./www           # serves ./www on :8080
./build/absurd -c absurd.conf          # or configure everything in a file
```

The doc root is snapshotted at startup, so **restart the server after changing files**.

absurd started out as a server written in AArch64 assembly on io_uring; that version is in the git history. The current C version keeps its design: in-memory snapshot, one pinned worker per CPU, privilege drop and a seccomp sandbox.

## Building

Requirements: Linux ≥ 3.17 on x86_64 or arm64, a C compiler, and OpenSSL with static libraries. On Debian/Ubuntu that's `libssl-dev`; on Alpine it's `openssl-dev openssl-libs-static linux-headers`.

```sh
make                 # native build (x86_64 or arm64): build/absurd
make NO_TLS=1        # without OpenSSL; tls listeners are then refused at startup
make cross-arm64     # arm64 binary on an x86_64 Debian/Ubuntu host: build/arm64/absurd
                     #   (apt install gcc-aarch64-linux-gnu libssl-dev:arm64)
```

The binary is statically linked, so it runs on any Linux distribution, or in a `scratch` container:

```sh
docker build -t absurd .
docker run --rm -p 8080:8080 -v "$PWD/www:/www:ro" absurd

# with a config file and certificates
docker run --rm -p 8080:8080 -p 8443:8443 -v "$PWD/www:/www:ro" \
  -v "$PWD/absurd.conf:/absurd.conf:ro" -v "$PWD/certs:/certs:ro" absurd -c /absurd.conf
```

## Usage

```
absurd [-c config] [-p port] [-t threads] [document-root]
```

- **`-c FILE`:** read a config file (see below).
- **`-p PORT`:** port of the first listener (default 8080).
- **`-t N`:** worker threads (default: one per CPU).
- **document root:** the directory to serve (default `.`).

`-p`, `-t` and the document root override the config file, wherever they appear on the command line. absurd must start as root to drop privileges to `nobody`. Started as another user, it keeps that user and serves what that user can read.

## Configuration

`absurd -c FILE` reads a config file: one directive per line, with `#` comments. See [`absurd.conf.example`](absurd.conf.example). A site with HTTPS, an API backend and the challenge in front of everything:

```
listen 80
listen 443 tls
tls_cert /etc/absurd/fullchain.pem
tls_key  /etc/absurd/privkey.pem
root /srv/www
proxy /api/ 127.0.0.1:3000
challenge /
```

| directive | meaning |
|---|---|
| `listen [IPv4:]PORT [tls]` | listening address; may be repeated (default `8080`) |
| `tls_cert FILE` / `tls_key FILE` | PEM certificate chain and key for `tls` listeners |
| `root DIR` | document root (default `.`) |
| `threads N` | worker threads (default: one per CPU) |
| `proxy PREFIX IPv4:PORT` | forward requests under `PREFIX` to an upstream |
| `challenge PREFIX` | require the JS challenge under `PREFIX` (`/` = everything) |
| `challenge_difficulty BITS` | proof-of-work difficulty, 1–32 (default 16) |
| `challenge_ttl SECONDS` | lifetime of the clearance cookie (default 3600) |
| `header_timeout`, `idle_timeout`, `send_timeout`, `upstream_timeout` | seconds (15, 30, 60, 60) |
| `max_body BYTES` | largest request body skipped on static targets (default 1 MiB) |

Errors are reported as `file:line: message`, and absurd exits with status 2.

## HTTP conformance

What absurd does with requests:

- **Methods:** GET, HEAD and OPTIONS (including `OPTIONS *`) are served.
  - POST, PUT, DELETE, PATCH and TRACE get 405 with `Allow` on static paths. They are forwarded on proxied paths.
  - CONNECT gets 405. Unknown methods get 501; method names are case-sensitive.
- **Request targets:** origin-form, absolute-form (`GET http://host/path`) and asterisk-form are accepted.
  - Characters outside RFC 3986 get 400 (including `#`, `"`, `<`, `\`, raw non-ASCII), as do bad percent-escapes and `%00`.
- **Versions:** HTTP/1.0 and 1.1. Higher 1.x minors are treated as 1.1; other majors get 505.
- **Header fields:** names must be tokens, and obs-fold is rejected.
  - Duplicate, missing (on 1.1) or invalid `Host` gets 400.
  - Bare CR, bare LF, NUL and other control characters anywhere in the head get 400.
- **Message bodies:** `Content-Length` and `chunked` (with extensions and trailers) are parsed and framed exactly. On static targets the body is read and discarded, so the connection stays usable.
  - These get 400 and close: `Transfer-Encoding` together with `Content-Length`, chunked that isn't last or appears twice, `Transfer-Encoding` on HTTP/1.0, and invalid or repeated `Content-Length`.
  - Unknown codings get 501.
- **Expect:** `Expect: 100-continue` is answered with `100 Continue` when the body is going to a proxy. Static targets get the final response and a close. Other expectations get 417.
- **Persistence:** `Connection` is parsed as a token list. HTTP/1.1 keeps the connection alive, and HTTP/1.0 does with `keep-alive`. Pipelining works.
  - Error responses close gracefully: absurd shuts down its sending side, then drains input, so the response isn't lost to a TCP reset.
- **Conditional requests:** `If-Match`, `If-Unmodified-Since` (412), `If-None-Match` and `If-Modified-Since` (304) are evaluated in RFC 9110 §13.2.2 order.
  - Entity-tags use strong or weak comparison as required.
  - All three HTTP-date formats are accepted (IMF-fixdate, RFC 850, asctime).
- **Range requests:** single byte ranges `a-b`, `a-` and `-n` get 206, and unsatisfiable ranges get 416 with `Content-Range: bytes */len`.
  - `If-Range` with an entity-tag or date is honoured.
  - Requests with several ranges are answered with the full 200 response.
- **Responses:** responses carry `Date`, `Server`, `ETag`, `Last-Modified` (never later than the server's clock), `Accept-Ranges` and `X-Content-Type-Options: nosniff`.
  - 304 responses carry the validators only.
  - 1xx responses are never sent to HTTP/1.0 clients.
  - A request head that takes longer than `header_timeout` gets 408.
- **Limits:** request targets over 2 KiB get 414, heads over 16 KiB get 431, and static request bodies over `max_body` get 413.

## Reverse proxy

`proxy /api/ 127.0.0.1:3000` sends every request whose decoded path starts with `/api/` to that upstream, with the path unchanged. absurd acts as a gateway (RFC 9110 §7.6):

- **Request to the upstream:**
  - Hop-by-hop fields are removed: `Connection`, every field named in it, `Keep-Alive`, `Proxy-Connection`, `TE`, `Transfer-Encoding`, `Upgrade`.
  - Added fields: `Via: 1.1 absurd`, `X-Forwarded-For` (replacing any sent by the client), `X-Forwarded-Proto` and `Connection: close`.
  - For absolute-form targets, `Host` comes from the target.
  - Paths with `.` or `..` segments get 400, so `/api/../admin` can't reach the upstream.
- **Bodies:** request bodies stream to the upstream as they arrive. Response bodies stream back with backpressure.
  - `Content-Length` and chunked responses keep the client connection alive.
  - For HTTP/1.0 clients, chunked bodies are de-chunked.
  - Close-delimited responses close the client connection.
  - 1xx responses are relayed; `101` isn't supported, so WebSocket upgrades are not proxied.
- **Errors:**
  - Unreachable upstream, malformed head, conflicting `Content-Length` or obs-fold: 502.
  - Upstream silent for `upstream_timeout`: 504.
  - Truncated body: the client connection is closed.

The upstream gets one connection per request (no pooling), and upstream addresses are IPv4 literals (there's no DNS).

## JS challenge (flood protection)

`challenge /` makes clients prove they run JavaScript before they get content:

1. A request without a valid `absurd_clearance` cookie gets a small `403` page with `Cache-Control: no-store`. Its script searches for `n` such that `SHA-256(nonce ‖ n)` starts with `challenge_difficulty` zero bits. Then it stores the result in the `absurd_pow` cookie and reloads.
2. absurd verifies the solution with one hash. It answers `307` back to the same URL and sets `absurd_clearance` (`HttpOnly`, `SameSite=Lax`, and `Secure` over TLS).
3. Requests with a valid clearance cookie pass. With the default difficulty a browser needs about 0.1–0.5 s, once per `challenge_ttl`.

No state is kept:

- The nonce holds a timestamp and a SipHash MAC of the client's IPv4 address. Solutions are accepted for 5 minutes.
- The clearance cookie is an expiry plus a MAC.
- The MAC key is random per process, so cookies become invalid when the server restarts.

The challenge stops clients that don't run JavaScript, and makes clients that do pay CPU time per IP address. It isn't a defence against volumetric floods. Clients behind a TLS terminator or another proxy all share that proxy's address.

## TLS

`listen 8443 tls` with `tls_cert` and `tls_key` serves HTTPS through OpenSSL:

- TLS 1.2 and 1.3; for TLS 1.2, ECDHE with AES-GCM or ChaCha20 ciphers.
- ALPN `http/1.1`, and no renegotiation.
- Certificates and keys are loaded before privileges are dropped.
- The random number generator is seeded before the sandbox starts.

## Security model

absurd is built so that request handling can't reach anything outside the snapshot taken at startup.

1. **Bind, then drop privileges.** Sockets are bound, and the config and TLS key are read, as root. Then absurd drops to uid/gid 65534 (`nobody`) and clears supplementary groups. Only after that does it read the doc root, so it can only serve files that `nobody` can read.
2. **Snapshot the doc root.** Every directory is opened relative to its parent with `O_NOFOLLOW`. Each file is `fstat`ed after opening and must be a regular file.
   - Skipped: symlinks, devices, sockets and FIFOs.
   - Dotfiles (`.git`, `.env`, `.htpasswd`, …) are never loaded.
   - Path traversal (`../`, `%2e%2e`, symlink escapes) can't work, because a request can only match a path that's in the table.
3. **Read-only memory.** File contents, pre-rendered headers and the hash table live in one arena that is `mprotect`ed read-only. The table is keyed with a random seed.
4. **No new privileges.** `PR_SET_NO_NEW_PRIVS` is set and the process is made non-dumpable.
5. **seccomp allow-list per worker thread.** Workers may only do socket I/O, epoll, memory management, time, futex and exit.
   - `socket()` is limited to `AF_INET`.
   - Any other system call fails with `EPERM`, including `open`, `execve` and `ptrace`.
   - Non-native ABIs (x32) kill the process.

## Tests

```sh
make && python3 test/run.py            # 40 test groups, ~15 s; add --slow for the 408 timeout test
make cross-arm64 && test/vm.sh         # the same suite against the arm64 build, in an arm64 VM
```

`test/run.py` generates a test site, a self-signed certificate and a config file. It starts absurd and a scripted upstream, then checks every response byte for byte. Coverage:

- static files, traversal and hidden files
- the conformance rules above, about 30 malformed requests and smuggling attempts
- conditional and range requests
- the proxy (header rewriting, both body framings, 1xx, 502/504, pipelines mixing proxied and static responses)
- the challenge, solved in Python
- TLS with ALPN, the config file errors
- a 5000-request pipeline, slow readers, byte-at-a-time and split requests, 2000 concurrent connections, connection churn, and fuzzing

`test/vm.sh` runs on any Linux host with `qemu-system-arm`, `qemu-user-static`, `cpio` and `openssl`. It downloads an Ubuntu arm64 kernel and busybox once, into `~/.cache/absurd-vm`. Then it boots them under `qemu-system-aarch64` and runs the suite against the cross-compiled binary. Because qemu's user-mode network is slow to connect, the VM run uses 200 concurrent connections instead of 2000.

## Performance

Setup: one absurd worker pinned to one core of a shared 4-vCPU x86_64 cloud VM (Xeon, 2.8 GHz), wrk on the other three cores, 96 keep-alive connections, serving the 37-byte test `index.html`. Each figure is the median of three runs of `bench/local.sh`, which you can run on your own machine.

| | absurd, one core | do-nothing server, same setup |
|---|---:|---:|
| pipelined, 16 requests per write | **1.32M req/s** | 1.87M req/s |
| one request at a time | 92k req/s | 104k req/s |

The do-nothing server is a 30-line epoll loop that answers every request with a fixed buffer, with no parsing and no checks. It shows what the kernel allows on this machine.

- **One request at a time,** throughput is limited by the kernel, not by absurd. Even the do-nothing server spends most of the core in TCP, and 27% just waking wrk's threads on the other CPUs. absurd is within run-to-run noise of it.
- **Pipelined,** the kernel cost is shared by 16 requests, and absurd's own work shows. That work is a full RFC 9112 parse and validation of every request, a hash-table lookup, and conditional and range checks.

What keeps that work small:
- the request head is scanned 16 bytes at a time with SSE2 or NEON
- responses are pre-rendered at startup
- the `Date` line is rendered once a second
- pipelined responses leave in one `sendmsg`, as one contiguous buffer
- large bodies are sent straight from the snapshot without copying

Workers share nothing (each has its own listener, steered to its CPU), so throughput scales with cores.

`bench/run.sh` and `bench/percore.sh` compare absurd with nginx:

```sh
docker build -t absurd-bench bench
docker run --rm -v "$PWD":/src absurd-bench sh -c 'cd /src && make clean && make && bench/run.sh'
docker run --rm -v "$PWD":/src absurd-bench sh -c 'cd /src && make clean && make && bench/percore.sh'
```

## Limits

- **No live reload.** File changes need a restart.
- **The whole doc root is held in memory.** The snapshot holds at most 1 GiB and 65k files; anything beyond that is skipped, with a warning at startup.
- **Not supported:** IPv6, HTTP/2, compression, directory listings, WebSocket proxying and upstream connection pooling.
