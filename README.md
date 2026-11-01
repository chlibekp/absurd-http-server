# absurd

absurd is a static-file web server for arm64 Linux, written in AArch64 assembly and built on io_uring. It's a 17 KB static binary with no libc and no allocator. Point it at a directory and it serves that directory, like nginx, but it never touches the filesystem after startup.

```sh
docker build -t absurd .
docker run --rm --security-opt seccomp=unconfined -p 8080:8080 \
  -v "$PWD/www:/www:ro" absurd                     # serves ./www on :8080
# options: absurd [-p port] [-t threads] [document-root]
```

The container needs `--security-opt seccomp=unconfined` because Docker's default seccomp profile blocks io_uring. absurd installs its own, much tighter filter at startup (see Security). It needs Linux 6.6 or newer on arm64.

The doc root is snapshotted at startup, so **restart the server after changing files** (`docker restart <name>`).

## Security model

absurd is secure by construction: request handling can't reach anything outside the snapshot taken at startup.

1. **Bind, then drop privileges.** The server binds its port as root, then drops to uid/gid 65534 (`nobody`) and clears supplementary groups. Only after that does it read the doc root, so it can only serve files that `nobody` can read.
2. **Snapshot the doc root.** Every directory is opened relative to its parent with `O_NOFOLLOW`. Each file is `fstat`ed after opening and must be a regular file.
   - Skipped: symlinks, devices, sockets and FIFOs.
   - Dotfiles (`.git`, `.env`, `.htpasswd`, …) are never loaded.
   - Nothing is loaded at request time, so there's no time-of-check/time-of-use race.
   - Path traversal (`../`, `%2e%2e`, symlink escapes) can't work, because a request can only match a path that's in the table.
3. **Read-only memory.** File contents, pre-rendered headers and the hash table live in one arena that is `mprotect`ed read-only. The hash table is keyed with a random seed from `getrandom`.
4. **No new privileges.** `PR_SET_NO_NEW_PRIVS` is set and the process is made non-dumpable.
5. **Locked-down io_uring.** Each ring is created disabled and limited to `ACCEPT`, `RECV`, `SENDMSG`, `CLOSE`, `TIMEOUT`, `ASYNC_CANCEL` and `SHUTDOWN`, with a fixed set of SQE flags. No further `io_uring_register` calls are allowed after that.
6. **seccomp allow-list.** Each worker then permits only `io_uring_enter`, `clock_gettime`, `exit`, `exit_group` and `rt_sigreturn`. Any other syscall kills the process. Even with code execution, an attacker couldn't open a file or start a process.

HTTP handling is strict:
- **Invalid bytes are rejected in one NEON pass:** control characters, DEL, bare CR, bare LF, and NUL anywhere in the request head.
- **Malformed requests get 400:** obs-fold, whitespace before the colon, duplicate `Host`, a missing `Host` on HTTP/1.1, absolute-form or `*` targets, bad percent-escapes, `%00`, and raw non-ASCII in the target.
- **No request bodies,** which rules out request smuggling. `Content-Length` other than 0 gets 413 and `Transfer-Encoding` gets 501; both close the connection.
- **Other errors:** methods other than GET/HEAD get 405 and the connection is closed. Unknown HTTP versions get 505. Targets over 2 KiB get 414, and header blocks over ~14 KiB get 431.
- **Timeouts against slowloris:** 15 s to deliver a complete header block, 30 s idle keep-alive, and 60 s for any single send to make progress.
- Every response carries `X-Content-Type-Options: nosniff`. No directory listings are ever generated.

## Features

- GET and HEAD.
- `index.html` for `/` and `/dir/`, plus a `301` from `/dir` to `/dir/` with a percent-encoded `Location`.
- MIME types for about 35 extensions. Text types are sent with `charset=utf-8`; anything else is `application/octet-stream`.
- An `ETag` (derived from mtime, size and inode), and `304 Not Modified` for `If-None-Match`, including `W/` and `*`.
- Keep-alive and `Connection: close` for HTTP/1.1, and `Connection: keep-alive` for HTTP/1.0. HTTP pipelining works too.
- Large files are sent in 1 MiB `sendmsg` chunks straight from memory.

## Performance

Measured on an Apple M2 in Docker's Linux VM (6 vCPU, kernel 6.10), serving the same `index.html` as nginx 1.26 configured with `sendfile`, `open_file_cache`, reuseport and pinned workers. Load comes from `wrk` on the same machine.

| | nginx | absurd |
|---|---:|---:|
| 1 server core, keep-alive | 181k req/s | **462k req/s** (2.5×) |
| 1 server core, pipelined ×16 | 96k req/s | **4.72M req/s** |
| 3 server cores vs 3 wrk cores, keep-alive | 550k req/s | **910k req/s** |
| 3 server cores vs 3 wrk cores, pipelined ×16 | 96k req/s | **5.17M req/s** |

nginx's pipelined numbers are hurt by `tcp_nopush`/`sendfile` interacting with pipelining. They're shown as measured.

How the speed is achieved:

- **One pinned thread per CPU, sharing nothing.** Each has its own `SO_REUSEPORT` listener. A classic-BPF program steers each connection to the CPU that took its SYN.
- **io_uring tuned for one owner per ring:** `SINGLE_ISSUER | DEFER_TASKRUN | NO_SQARRAY`, with the ring fd itself registered. One `io_uring_enter` handles up to 1024 completions, and no other syscalls happen per request.
- **Multishot accept into a sparse fixed-file table.** Sockets never enter the process fd table.
- **No formatting at request time.** A response is a `sendmsg` with three pieces: pre-rendered headers, a shared `Date:` line, and the file body. All three already sit in memory, so nothing is copied.
- **Up to 16 pipelined responses per `sendmsg`.** Each connection has one send in flight while the next batch accumulates in a second iovec array.
- **NEON parsing.** Finding the end of the header block and validating every byte happen in a single 16-bytes-per-step pass.
- **The `Date` line comes from a timer, not a clock call per request.** A multishot timer fires every second; the server renders the time into a spare buffer and switches to it. The same tick runs the timeout sweep.

## Tests and benchmarks

```sh
docker build -t absurd-bench bench
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench sh -c '
  cd /src && make && python3 bench/stress.py fixture /tmp/site && chmod -R a+rX /tmp/site &&
  (./build/absurd -t 2 /tmp/site &) && sleep 0.5 && python3 bench/stress.py run 8080 --slow'
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench /src/bench/percore.sh
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench /src/bench/run.sh
```

`bench/stress.py` checks every response byte for byte. It covers:

- traversal and symlink escapes, and hidden files
- smuggling attempts and about 20 kinds of malformed request
- size limits, ETag revalidation, HTTP/1.0 and `Connection` semantics
- a 5000-request mixed pipeline
- a slow reader pipelining 40 × 3 MB files
- byte-at-a-time requests, and requests split at every possible offset
- 3000 concurrent connections, plus connection churn with RSTs
- 1500 fuzzed requests
- the 15 s header timeout

## Limits

- **No live reload.** File changes need a restart.
- **The whole doc root is held in memory.** The snapshot holds at most 1 GiB and 65k files; anything beyond that is skipped, with a warning at startup.
- **Not supported:** range requests, compression, TLS (put a TLS terminator in front), HTTP/2, request bodies and directory listings.
- Each thread holds up to 8192 connections.
- **Closed sockets can be released late.** On 6.x kernels, the kernel releases a socket removed from the fixed-file table only after older in-flight requests finish. absurd sends FIN immediately through `shutdown()`, so clients aren't affected. The socket memory itself is freed within the idle timeout (≤ 60 s).
