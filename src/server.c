// Startup, worker threads and the connection state machine.
//
// Startup (one thread): parse arguments and the config file, bind one
// SO_REUSEPORT listener per thread and per address, load TLS keys, drop to
// uid/gid 65534, snapshot the document root, then start one pinned worker per
// CPU. Each worker installs a seccomp allow-list (no open, no exec, sockets
// only AF_INET) and runs an epoll loop.
#include "absurd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

enum { EP_REG = 1u << 31, LINGER_SECS = 2 };

static int nthreads;
static int cpus[MAX_THREADS], ncpus;
static int lfds[MAX_THREADS][MAX_LISTEN];
static bool steered, dropped;

// ---------------------------------------------------------------- epoll
void ep_set(struct worker *w, int fd, void *ptr, uint32_t *cur, uint32_t want) {
    if ((*cur & EP_REG) && (*cur & ~EP_REG) == want) return;
    struct epoll_event ev = {.events = want, .data.ptr = ptr};
    epoll_ctl(w->ep, (*cur & EP_REG) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev);
    *cur = want | EP_REG;
}

static void set_date(struct worker *w) {
    char d[30];
    fmt_http_date(d, w->now);
    static const char *const tail[3] = {"\r\n", "Connection: close\r\n\r\n", "Connection: keep-alive\r\n\r\n"};
    for (int i = 0; i < 3; i++)
        w->datelen[i] = (size_t)snprintf(w->date[i], sizeof w->date[i], "Date: %s\r\n%s", d, tail[i]);
}

static int64_t now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}

// ---------------------------------------------------------------- connections
static void conn_new(struct worker *w, const struct listener *l, int fd, uint32_t peer) {
    struct conn *c = calloc(1, sizeof *c);
    char *in = malloc(INCAP + 64);   // slack: the parser may peek a few bytes past the data
    if (!c || !in) {
        free(c);
        free(in);
        close(fd);
        return;
    }
    c->type = EV_CONN;
    c->fd = fd;
    c->w = w;
    c->ls = l->cfg;
    c->in = in;
    c->peer = peer;
    c->last = w->now;
    if (l->cfg->tls) {
        c->ssl = tls_new(fd);
        if (!c->ssl) {
            free(in);
            free(c);
            close(fd);
            return;
        }
        c->handshaking = true;
    }
    c->next = w->conns;
    if (w->conns) w->conns->prev = c;
    w->conns = c;
    ep_set(w, fd, c, &c->events, EPOLLIN);
}

void worker_bury(struct worker *w, void *obj) {
    if (w->ndead == w->deadcap) {
        w->deadcap = w->deadcap ? w->deadcap * 2 : 64;
        w->dead = realloc(w->dead, w->deadcap * sizeof *w->dead);
        if (!w->dead) die("realloc");
    }
    w->dead[w->ndead++] = obj;
}

void conn_close(struct conn *c) {
    struct worker *w = c->w;
    if (c->type != EV_CONN) return;
    if (c->px) proxy_abort(c->px);
    if (c->ssl) tls_free(c->ssl);
    close(c->fd);
    if (c->prev) c->prev->next = c->next;
    else w->conns = c->next;
    if (c->next) c->next->prev = c->prev;
    out_free(&c->out);
    free(c->in);
    c->type = 0;
    worker_bury(w, c);
}

static bool paused(const struct conn *c) {
    return c->out.pending >= OUT_HIGH || c->out.responses >= MAX_PIPELINE;
}

static void read_input(struct conn *c) {
    while (!c->eof && !c->closing && c->inlen < INCAP) {
        ssize_t n;
        if (c->ssl) {
            n = tls_read(c->ssl, c->in + c->inlen, INCAP - c->inlen);
            if (n == -1) break;
            if (n == -2) {
                c->closing = true;
                break;
            }
        } else {
            n = recv(c->fd, c->in + c->inlen, INCAP - c->inlen, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) break;
                c->closing = true;
                break;
            }
        }
        if (n == 0) {
            c->eof = true;
            break;
        }
        size_t room = INCAP - c->inlen;
        c->inlen += (size_t)n;
        c->last = c->w->now;
        if (!c->ssl && (size_t)n < room) break;   // drained; TLS may still hold decrypted records
    }
}

static void write_output(struct conn *c) {
    struct outq *q = &c->out;
    while (q->pending && !c->closing) {
        ssize_t n;
        if (c->ssl) {
            struct seg *s = &q->segs[q->head];
            const char *p = (s->p ? s->p : q->buf + s->off) + q->done;
            n = tls_write(c->ssl, p, s->len - q->done);
            if (n == -1) break;
            if (n == -2) {
                c->closing = true;
                break;
            }
        } else {
            struct iovec iov[64];
            int cnt = 0;
            for (size_t i = q->head; i < q->nseg && cnt < 64; i++, cnt++) {
                struct seg *s = &q->segs[i];
                const char *p = s->p ? s->p : q->buf + s->off;
                size_t skip = i == q->head ? q->done : 0;
                iov[cnt].iov_base = (void *)(p + skip);
                iov[cnt].iov_len = s->len - skip;
            }
            struct msghdr m = {.msg_iov = iov, .msg_iovlen = (size_t)cnt};
            n = sendmsg(c->fd, &m, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) break;
                c->closing = true;
                break;
            }
        }
        c->last = c->w->now;
        q->pending -= (size_t)n;
        size_t left = (size_t)n;
        while (left) {
            struct seg *s = &q->segs[q->head];
            size_t avail = s->len - q->done;
            if (left < avail) {
                q->done += left;
                left = 0;
            } else {
                left -= avail;
                q->head++;
                q->done = 0;
            }
        }
    }
    if (!q->pending) {   // everything sent: reuse the queue from the start
        q->nseg = q->head = q->done = 0;
        q->blen = 0;
        q->responses = 0;
    } else if (q->head >= 64 || q->blen >= 4 * OUT_HIGH) {
        // a long stream: drop what was sent so the queue does not grow without bound
        size_t keep = q->blen;
        for (size_t i = q->head; i < q->nseg; i++)
            if (!q->segs[i].p && q->segs[i].off < keep) keep = q->segs[i].off;
        memmove(q->buf, q->buf + keep, q->blen - keep);
        q->blen -= keep;
        memmove(q->segs, q->segs + q->head, (q->nseg - q->head) * sizeof *q->segs);
        q->nseg -= q->head;
        q->head = 0;
        for (size_t i = 0; i < q->nseg; i++)
            if (!q->segs[i].p) q->segs[i].off -= keep;
    }
}

static void parse_requests(struct conn *c) {
    struct request req;
    while (!c->drain && !c->px && !c->closing && !paused(c)) {
        if (c->discarding) {   // the body of a request we answered ourselves
            const char *p = c->in + c->inpos;
            int st = framer_step(&c->body, &p, c->in + c->inlen, NULL, NULL);
            c->inpos = (size_t)(p - c->in);
            if (st == FS_MORE) break;
            c->discarding = false;
            if (st == FS_ERR) c->drain = true;   // malformed: close after the response
            continue;
        }
        if (c->inpos == c->inlen) break;
        const char *end = http_parse(c->w, c->in + c->inpos, c->in + c->inlen, c->peer, c->ls->tls, &req);
        if (!end) {
            if (c->inlen - c->inpos >= HEADMAX) {   // a head larger than we accept
                c->inpos = c->inlen;
                http_status(&c->out, c->w, 431, true, false);
                c->out.responses++;
                c->drain = true;
            } else if (!c->partial) {
                c->partial = true;
                c->rstart = c->w->now;
            }
            break;
        }
        c->inpos = (size_t)(end - c->in);
        c->partial = false;
        if (req.kind == K_PROXY) {
            proxy_start(c, &req);
            continue;
        }
        http_respond(c, &req);
        if (req.bmode != BM_NONE && !c->drain) {
            framer_init(&c->body, req.bmode, req.blen);
            c->discarding = true;
        }
    }
}

void conn_update(struct conn *c) {
    uint32_t want = 0;
    if (c->handshaking) {
        want = tls_wants_write(c->ssl) ? EPOLLOUT : EPOLLIN;
    } else if (c->lingering) {
        want = EPOLLIN;
    } else {
        if (!c->eof && c->inlen < INCAP && (c->px || (!paused(c) && !c->drain))) want |= EPOLLIN;
        if (c->out.pending) want |= EPOLLOUT;
    }
    ep_set(c->w, c->fd, c, &c->events, want);
}

// Graceful close (RFC 9112 9.6): stop writing, then read and discard until the
// client closes too, so a response is not destroyed by a reset.
static void start_linger(struct conn *c) {
    if (c->ssl) {
        tls_free(c->ssl);
        c->ssl = NULL;
    }
    shutdown(c->fd, SHUT_WR);
    c->lingering = true;
    c->linger_since = c->w->now;
}

void conn_process(struct conn *c) {
    if (c->type != EV_CONN) return;
    for (;;) {
        if (c->closing) {
            conn_close(c);
            return;
        }
        if (c->handshaking) {
            int r = tls_handshake(c->ssl);
            if (r < 0) {
                conn_close(c);
                return;
            }
            if (r == 0) break;
            c->handshaking = false;
            c->last = c->w->now;
        }
        if (c->lingering) {
            char junk[4096];
            for (;;) {
                ssize_t n = recv(c->fd, junk, sizeof junk, 0);
                if (n > 0) continue;
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) break;
                conn_close(c);
                return;
            }
            break;
        }
        if (c->px || !paused(c)) read_input(c);
        for (;;) {
            parse_requests(c);
            if (!c->px) break;
            proxy_pump(c->px);
            if (c->px) break;
            // the exchange finished: pipelined requests behind it can go on
        }
        if (c->inpos) {
            memmove(c->in, c->in + c->inpos, c->inlen - c->inpos);
            c->inlen -= c->inpos;
            c->inpos = 0;
        }
        write_output(c);
        if (c->closing) {
            conn_close(c);
            return;
        }
        if (c->px) {
            if (c->px->throttled && c->out.pending < OUT_HIGH) continue;   // the client caught up
            break;
        }
        if (c->out.pending) break;
        if (c->drain) {
            start_linger(c);
            continue;
        }
        if (c->eof) {   // nothing more can arrive and everything is answered
            conn_close(c);
            return;
        }
        // output drained: requests held back by the pipeline limit can go on
        if (c->inlen && !c->partial && !c->discarding) continue;
        break;
    }
    conn_update(c);
}

static void sweep(struct worker *w) {
    for (struct conn *c = w->conns, *next; c; c = next) {
        next = c->next;
        int64_t idle = w->now - c->last;
        if (c->px) {
            proxy_sweep(c->px, w->now);   // may close c
        } else if (c->lingering) {
            if (w->now - c->linger_since > LINGER_SECS) conn_close(c);
        } else if (c->handshaking) {
            if (idle > cfg.to_header) conn_close(c);
        } else if (c->out.pending) {
            if (idle > cfg.to_send) conn_close(c);
        } else if (c->partial) {
            if (w->now - c->rstart > cfg.to_header) {   // slow headers: 408, then close
                c->partial = false;
                c->inpos = c->inlen;
                http_status(&c->out, w, 408, true, false);
                c->drain = true;
                conn_process(c);
            }
        } else if (idle > cfg.to_idle) {
            conn_close(c);
        }
    }
}

static void on_accept(struct worker *w, struct listener *l) {
    for (int i = 0; i < 64; i++) {
        struct sockaddr_in sa;
        socklen_t len = sizeof sa;
        int fd = accept4(l->fd, (struct sockaddr *)&sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                for (int j = 0; j < cfg.nlisten; j++) ep_set(w, w->ls[j].fd, &w->ls[j], &w->ls[j].events, 0);
                w->accept_paused = true;   // retry on the next tick
            }
            return;
        }
        conn_new(w, l, fd, sa.sin_addr.s_addr);
    }
}

void worker_run(struct worker *w) {
    struct epoll_event ev[256];
    w->now = now_s();
    set_date(w);
    for (int i = 0; i < cfg.nlisten; i++) ep_set(w, w->ls[i].fd, &w->ls[i], &w->ls[i].events, EPOLLIN);
    int64_t tick = w->now;
    for (;;) {
        int n = epoll_wait(w->ep, ev, 256, 1000);
        w->now = now_s();
        if (w->now != tick) {
            tick = w->now;
            set_date(w);
            if (w->accept_paused) {
                w->accept_paused = false;
                for (int i = 0; i < cfg.nlisten; i++) ep_set(w, w->ls[i].fd, &w->ls[i], &w->ls[i].events, EPOLLIN);
            }
            sweep(w);
        }
        for (int i = 0; i < n; i++) {
            int type = *(int *)ev[i].data.ptr;
            if (type == EV_LISTEN)
                on_accept(w, ev[i].data.ptr);
            else if (type == EV_CONN)
                conn_process(ev[i].data.ptr);
            else if (type == EV_UPSTREAM)
                proxy_event(ev[i].data.ptr, ev[i].events);
        }
        for (size_t i = 0; i < w->ndead; i++) free(w->dead[i]);
        w->ndead = 0;
    }
}

// ---------------------------------------------------------------- sandbox
#if defined(__x86_64__)
#define ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ARCH_NR AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture"
#endif

// Allow-list for the serving phase. Everything else fails with EPERM: no
// open, no exec, no ptrace; socket() only for AF_INET.
void sandbox(void) {
    static const int allow[] = {
        SYS_read, SYS_write, SYS_readv, SYS_writev, SYS_close, SYS_epoll_ctl, SYS_epoll_pwait,
        SYS_accept4, SYS_connect, SYS_setsockopt, SYS_getsockopt, SYS_getsockname, SYS_getpeername,
        SYS_shutdown, SYS_sendto, SYS_recvfrom, SYS_sendmsg, SYS_recvmsg, SYS_clock_gettime,
        SYS_gettimeofday, SYS_futex, SYS_madvise, SYS_munmap, SYS_mmap, SYS_mremap, SYS_brk, SYS_mprotect,
        SYS_getrandom, SYS_exit, SYS_exit_group, SYS_rt_sigreturn, SYS_rt_sigprocmask, SYS_sched_yield,
        SYS_getpid, SYS_gettid, SYS_restart_syscall, SYS_clock_nanosleep, SYS_nanosleep,
#ifdef SYS_epoll_wait
        SYS_epoll_wait,
#endif
#ifdef SYS_epoll_pwait2
        SYS_epoll_pwait2,
#endif
#ifdef SYS_rseq
        SYS_rseq,
#endif
    };
    enum { N = sizeof allow / sizeof *allow };
    struct sock_filter f[N + 16];
    int k = 0;
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);   // x32 ABI
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
    // socket(AF_INET, ...) only
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 4);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 1);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    for (int i = 0; i < N; i++) {
        f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)allow[i], (unsigned char)(N - i), 0);
    }
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = {.len = (unsigned short)k, .filter = f};
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) die("installing the seccomp filter");
}

// ---------------------------------------------------------------- threads
static void *thread_main(void *arg) {
    struct worker *w = arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpus[w->id % ncpus], &set);
    sched_setaffinity(0, sizeof set, &set);
    w->ep = epoll_create1(EPOLL_CLOEXEC);
    if (w->ep < 0) die("epoll_create1");
    for (int i = 0; i < cfg.nlisten; i++) {
        w->ls[i].type = EV_LISTEN;
        w->ls[i].fd = lfds[w->id][i];
        w->ls[i].cfg = &cfg.listen[i];
    }
    sandbox();
    worker_run(w);
    return NULL;
}

static int listen_on(const struct listener_cfg *l) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) die("socket");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one)) die("SO_REUSEPORT");
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);   // inherited by accepted sockets
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(l->port), .sin_addr.s_addr = l->addr};
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa)) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &l->addr, ip, sizeof ip);
        fatal("bind %s:%u: %s", ip, l->port, strerror(errno));
    }
    if (listen(fd, 65535)) die("listen");
    return fd;
}

_Noreturn static void usage(void) {
    fputs("usage: absurd [-c config] [-p port] [-t threads] [document-root]\n", stderr);
    exit(2);
}

int main(int argc, char **argv) {
    config_defaults();
    int port = 0, threads = 0;
    const char *root = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) usage();
        if ((!strcmp(a, "-p") || !strcmp(a, "-t") || !strcmp(a, "-c")) && i + 1 == argc) usage();
        if (!strcmp(a, "-c")) {
            config_load(argv[++i]);
        } else if (!strcmp(a, "-p")) {
            port = atoi(argv[++i]);
            if (port < 1 || port > 65535) usage();
        } else if (!strcmp(a, "-t")) {
            threads = atoi(argv[++i]);
            if (threads < 1) usage();
        } else if (a[0] == '-') {
            usage();
        } else {
            root = a;
        }
    }
    if (root) cfg.root = root;
    if (threads) cfg.threads = threads > MAX_THREADS ? MAX_THREADS : threads;
    if (!cfg.nlisten) {
        cfg.listen[0] = (struct listener_cfg){.addr = 0, .port = 8080, .tls = false};
        cfg.nlisten = 1;
    }
    if (port) cfg.listen[0].port = (uint16_t)port;

    if (getrandom(&g_seed, sizeof g_seed, 0) != sizeof g_seed || getrandom(g_key, sizeof g_key, 0) != sizeof g_key)
        die("getrandom");
    g_start = now_s();
    signal(SIGPIPE, SIG_IGN);

    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) == 0)
        for (int i = 0; i < CPU_SETSIZE && ncpus < MAX_THREADS; i++)
            if (CPU_ISSET(i, &set)) cpus[ncpus++] = i;
    if (!ncpus) cpus[ncpus++] = 0;
    nthreads = cfg.threads ? cfg.threads : ncpus;

    // fixed per-connection memory is small, but allow many sockets
    struct rlimit rl;
    if (!getrlimit(RLIMIT_NOFILE, &rl)) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    for (int t = 0; t < nthreads; t++)
        for (int i = 0; i < cfg.nlisten; i++) lfds[t][i] = listen_on(&cfg.listen[i]);

    // CPU steering: thread i on CPU i for all i -> "ld [SKF_AD_CPU]; ret A"
    if (ncpus == nthreads && cpus[ncpus - 1] == ncpus - 1) {
        struct sock_filter code[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned)(SKF_AD_OFF + SKF_AD_CPU)),
            BPF_STMT(BPF_RET | BPF_A, 0),
        };
        struct sock_fprog prog = {.len = 2, .filter = code};
        steered = true;
        for (int i = 0; i < cfg.nlisten; i++)
            if (setsockopt(lfds[0][i], SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof prog)) steered = false;
    }

    tls_init();   // keys are read while still root

    if (getuid() == 0) {   // drop root before touching the document root
        if (setgroups(0, NULL) || setgid(65534) || setuid(65534)) die("dropping privileges");
        dropped = true;
    }
    snapshot_load(cfg.root);

    printf("absurd: serving %zu files (%zu bytes) from %s, %d threads", snap_files, snap_bytes, cfg.root, nthreads);
    if (steered) printf(", cpu-steered");
    if (dropped) printf(", running as nobody");
    printf("\n");
    for (int i = 0; i < cfg.nlisten; i++) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg.listen[i].addr, ip, sizeof ip);
        printf("absurd: listening on %s %s:%u\n", cfg.listen[i].tls ? "https" : "http", ip, cfg.listen[i].port);
    }
    for (int i = 0; i < cfg.nroutes; i++) printf("absurd: proxy %s -> %s\n", cfg.routes[i].prefix, cfg.routes[i].host);
    for (int i = 0; i < cfg.nchal; i++)
        printf("absurd: JS challenge on %s (difficulty %d bits)\n", cfg.chal[i], cfg.ch_bits);
    if (snap_skipped) printf("absurd: warning: skipped %zu files (1 GiB snapshot cap or table full)\n", snap_skipped);
    fflush(stdout);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("PR_SET_NO_NEW_PRIVS");
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    static struct worker workers[MAX_THREADS];
    for (int t = 1; t < nthreads; t++) {
        workers[t].id = t;
        pthread_t th;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, 256 * 1024);
        if (pthread_create(&th, &at, thread_main, &workers[t])) die("pthread_create");
    }
    workers[0].id = 0;
    thread_main(&workers[0]);
    return 0;
}
