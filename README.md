# absurd

An HTTP/1.1 server written in AArch64 assembly for Linux. It's a 4.6 KB static binary with no libc and no allocator, and it makes no syscalls per request.

Every request gets the same `200 Hello, World!` response, the same contract as the TechEmpower "plaintext" benchmark.

## Results

All numbers come from one Apple M2 running Docker's Linux VM (6 vCPU, kernel 6.10). The load generator is `wrk` on the same machine. absurd is compared with nginx 1.26, configured the same way (`return 200`, access log off, reuseport, pinned workers).

**One server core** (CPU 0), with `wrk` driving it from the other 5 cores:

| | nginx | absurd | |
|---|---:|---:|---:|
| keep-alive | 322k req/s | **614k req/s** | 1.9× |
| pipelined ×16 | 299k req/s | **7.84M req/s** | 26× |
| pipelined ×64 | — | **9.94M req/s** | |
| pipelined ×256 | — | **10.9M req/s** | |

**3 server cores vs 3 wrk cores:** keep-alive gives 905k vs 770k req/s, and pipelined ×16 gives 6.08M vs 1.04M req/s. In the pipelined run absurd used only about 46% of its 3 cores while wrk was pegged at 98%, so `wrk` is the bottleneck there, not the server.

## How it works

- **One pinned thread per CPU, sharing nothing.** Each thread has its own `SO_REUSEPORT` listener, its own io_uring, its own buffers and its own connection table. Threads never share memory they write, so there are no locks and no atomics.
- **Classic-BPF connection steering.** When thread *i* runs on CPU *i*, the program `ld [SKF_AD_CPU]; ret A` is attached to the reuseport group. The kernel then hands each connection to the listener on the CPU that processed its SYN.
- **io_uring set up for one owner.** The ring uses `SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN | NO_SQARRAY | SUBMIT_ALL`, and the ring fd itself is registered, so `io_uring_enter` skips the fd lookup. One `io_uring_enter` call submits all the work produced by up to 1024 completions and waits for the next batch.
- **Multishot accept into fixed files.** Accepted sockets go straight into a sparse registered-file table and never appear in the process fd table. There is no `fdget` and no refcount traffic on the hot path.
- **Multishot recv from a provided-buffer ring.** One armed recv per connection, kept for its lifetime. The kernel picks the buffer and the server returns it to the ring as soon as it has been scanned. The ring tail is published once per batch.
- **NEON request counting.** Each 16-byte block costs 2 `cmeq`, 3 `ext`, 3 `and` and 1 `sub` to find every `\r\n\r\n`. The last 4 bytes of each buffer are carried into the 16-byte prefix of the next one, so a terminator split across reads, even a byte at a time, is still found. A zeroed tail pad keeps stale buffer bytes from producing false matches.
- **Pre-rendered responses.** Each thread keeps 128 copies of the response laid out back to back. *N* pipelined requests are answered by a single `send()` of `N × 131` bytes pointing into that static memory: no formatting, no copying, no per-connection write buffer.
- **The Date header comes from a kernel timer.** A multishot `IORING_OP_TIMEOUT` fires once a second. The server renders the date into whichever of the two response blobs is idle, then switches to it. Sends still in flight keep reading the other blob, which won't be rewritten for another second. This is the only `clock_gettime` call, once a second per thread.
- **Byte order stays correct under backpressure.** Sends use `MSG_WAITALL`. Each connection has at most one send in flight, and responses that arrive in the meantime are counted and coalesced into the next send. A generation counter in each connection's user_data discards completions for slots that have since been reused.
  - Skipping send completions (`CQE_SKIP_SUCCESS`) was tried and measured: the gain was within noise, and a stalled reader could then get interleaved bytes, so it was dropped.
- **`TCP_DEFER_ACCEPT` and `TCP_NODELAY`** are set on the listener and inherited by accepted sockets. A connection is only accepted once its first request has arrived, so the first recv finds data immediately.

## Build and run

The project needs Linux ≥ 6.6 on arm64. Docker's default seccomp profile blocks io_uring, so containers must run with it disabled.

```sh
# build + run in Docker (works on Apple Silicon)
docker build -t absurd .
docker run --rm --security-opt seccomp=unconfined -p 8080:8080 absurd          # all CPUs
docker run --rm --security-opt seccomp=unconfined -p 8080:8080 absurd 8080 4   # port, threads

# or natively on arm64 Linux with binutils
make && ./build/absurd [port] [threads]
```

## Tests and benchmarks

```sh
docker build -t absurd-bench bench
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench sh -c \
  'cd /src && make && (./build/absurd 8080 2 >/dev/null &) && sleep 0.5 && python3 bench/stress.py'
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench /src/bench/percore.sh
docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src absurd-bench /src/bench/run.sh
```

`bench/stress.py` checks every response byte for byte. It covers:

- pipelines of 20k requests in a single write
- a client that sends 200k pipelined requests without reading
- byte-at-a-time requests, and requests split at every possible offset
- 3k concurrent connections, and connect/close churn
- RST in the middle of a pipeline
- garbage input

A separate check confirmed that 40k sequential connections on one thread (more than its 16,384 fixed-file slots) reuse slots correctly.

## Limits (deliberate)

- The request line, method and path are never looked at. Each `\r\n\r\n` counts as one request and gets the canned response.
- Request bodies and `Connection: close` aren't supported, and there's no HTTP/1.0 close-delimited mode. This is a keep-alive server only.
- Each thread holds up to 16,384 connections, the size of its fixed-file table (`MAXCONN`).
