// Reverse proxy ("proxy PREFIX IPv4:PORT"). absurd acts as a gateway (RFC 9110
// 7.6): one upstream connection per request, hop-by-hop fields removed in both
// directions, Via and X-Forwarded-* added, the request body streamed as
// received (Content-Length or chunked), the response body streamed back with
// framing the client can use (chunked is removed for HTTP/1.0 clients).
#include "absurd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

enum { MAXTOK = 16 };

struct toks {
    struct span t[MAXTOK];
    int n;
};

static void trim(const char **p, const char **e) {
    while (*p < *e && (**p == ' ' || **p == '\t')) (*p)++;
    while (*e > *p && ((*e)[-1] == ' ' || (*e)[-1] == '\t')) (*e)--;
}

static bool name_is(const char *l, size_t nl, const char *lit) {
    return nl == strlen(lit) && !strncasecmp(l, lit, nl);
}

// the field names listed in Connection header fields of [h, end)
static void connection_tokens(const char *h, const char *end, struct toks *t) {
    t->n = 0;
    for (const char *l = h; l < end && !(l[0] == '\r' && l[1] == '\n');) {
        const char *lf = memchr(l, '\n', (size_t)(end - l));
        const char *colon = memchr(l, ':', (size_t)(lf - l));
        if (colon && name_is(l, (size_t)(colon - l), "connection")) {
            for (const char *s = colon + 1; s < lf - 1;) {
                const char *c = memchr(s, ',', (size_t)(lf - 1 - s));
                if (!c) c = lf - 1;
                const char *a = s, *b = c;
                trim(&a, &b);
                if (a < b && t->n < MAXTOK) t->t[t->n++] = (struct span){a, b};
                s = c + 1;
            }
        }
        l = lf + 1;
    }
}

static bool hop_by_hop(const char *l, size_t nl, const struct toks *t) {
    static const char *const hop[] = {"connection", "keep-alive", "proxy-connection", "te",
                                      "transfer-encoding", "upgrade"};
    for (size_t i = 0; i < sizeof hop / sizeof *hop; i++)
        if (name_is(l, nl, hop[i])) return true;
    for (int i = 0; i < t->n; i++)
        if ((size_t)(t->t[i].e - t->t[i].p) == nl && !strncasecmp(l, t->t[i].p, nl)) return true;
    return false;
}

static void sb_add(struct proxy *px, const void *p, size_t n) {
    if (px->slen + n > UP_SCAP) n = UP_SCAP - px->slen;   // (the head always fits: it is < HEADMAX + 1 KiB)
    memcpy(px->sbuf + px->slen, p, n);
    px->slen += n;
}

static void sb_str(struct proxy *px, const char *s) {
    sb_add(px, s, strlen(s));
}

static void finish(struct proxy *px);

// Fail the exchange. Before any response byte reached the client it gets a
// 502/504; afterwards the client connection is closed mid-response.
static void fail(struct proxy *px, int status) {
    struct conn *c = px->c;
    if (!px->sent)
        http_status(&c->out, c->w, status, true, px->head_method);
    c->drain = true;
    px->close_client = true;
    finish(px);
}

void proxy_start(struct conn *c, struct request *r) {
    struct proxy *px = calloc(1, sizeof *px);
    if (!px) die("calloc");
    px->type = EV_UPSTREAM;
    px->c = c;
    px->rt = r->rt;
    px->sbuf = malloc(UP_SCAP);
    px->rbuf = malloc(UP_RCAP + 64);
    if (!px->sbuf || !px->rbuf) die("malloc");
    px->head_method = r->method == MT_HEAD;
    px->v11 = r->v11;
    px->ka = r->ka;
    px->close_client = r->close;
    px->last = c->w->now;
    framer_init(&px->reqf, r->bmode, r->blen);
    px->reqdone = r->bmode == BM_NONE;
    c->px = px;

    // ---- the request for the upstream
    sb_add(px, r->mth.p, (size_t)(r->mth.e - r->mth.p));
    sb_str(px, " ");
    sb_add(px, r->target.p, (size_t)(r->target.e - r->target.p));
    sb_str(px, " HTTP/1.1\r\n");
    struct toks t;
    connection_tokens(r->hdrs, r->end, &t);
    bool host = false;
    for (const char *l = r->hdrs; !(l[0] == '\r' && l[1] == '\n');) {
        const char *lf = memchr(l, '\n', (size_t)(r->end - l));
        size_t nl = (size_t)((const char *)memchr(l, ':', (size_t)(lf - l)) - l);
        bool skip = hop_by_hop(l, nl, &t) || name_is(l, nl, "expect") || name_is(l, nl, "x-forwarded-for") ||
                    name_is(l, nl, "x-forwarded-proto") || name_is(l, nl, "forwarded") || name_is(l, nl, "via");
        if (name_is(l, nl, "host")) {
            // absolute-form: the Host field is regenerated from the target (RFC 9112 3.2.2)
            if (r->absform) skip = true;
            else host = true;
        }
        if (!skip) sb_add(px, l, (size_t)(lf + 1 - l));
        l = lf + 1;
    }
    if (r->absform) {
        sb_str(px, "Host: ");
        sb_add(px, r->auth.p, (size_t)(r->auth.e - r->auth.p));
        sb_str(px, "\r\n");
    } else if (!host) {   // HTTP/1.0 without Host
        sb_str(px, "Host: ");
        sb_str(px, px->rt->host);
        sb_str(px, "\r\n");
    }
    if (r->bmode == BM_CHUNKED) sb_str(px, "Transfer-Encoding: chunked\r\n");
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->peer, ip, sizeof ip);
    char extra[256];
    snprintf(extra, sizeof extra, "X-Forwarded-For: %s\r\nX-Forwarded-Proto: %s\r\nVia: 1.1 absurd\r\nConnection: close\r\n\r\n",
             ip, c->ls->tls ? "https" : "http");
    sb_str(px, extra);

    // we read the body for the upstream, so we answer Expect: 100-continue ourselves
    if (r->expect && r->v11 && r->bmode != BM_NONE) out_add(&c->out, "HTTP/1.1 100 Continue\r\n\r\n", 25);

    px->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (px->fd < 0) {
        fail(px, 502);
        return;
    }
    int one = 1;
    setsockopt(px->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(px->fd, (const struct sockaddr *)&px->rt->addr, sizeof px->rt->addr) && errno != EINPROGRESS) {
        fail(px, 502);
        return;
    }
    ep_set(c->w, px->fd, px, &px->events, EPOLLOUT);
}

// Remove the upstream side; the client connection carries on (or closes).
static void finish(struct proxy *px) {
    struct conn *c = px->c;
    if (px->fd >= 0) close(px->fd);   // (closing removes it from epoll)
    if (!px->reqdone || px->close_client) c->drain = true;
    c->px = NULL;
    free(px->sbuf);
    free(px->rbuf);
    px->type = 0;
    worker_bury(c->w, px);   // events for it may still be queued in this batch
}

void proxy_abort(struct proxy *px) {
    px->close_client = true;
    finish(px);
}

// RFC 9112 6.3: how long is the response body?
static int response_framing(struct proxy *px, int status, const char *h, const char *end, uint64_t *len) {
    if (px->head_method || status / 100 == 1 || status == 204 || status == 304) return BM_NONE;
    bool te = false, te_last_chunked = false, cl = false;
    px->te_other = false;
    uint64_t clv = 0;
    for (const char *l = h; !(l[0] == '\r' && l[1] == '\n');) {
        const char *lf = memchr(l, '\n', (size_t)(end - l));
        const char *colon = memchr(l, ':', (size_t)(lf - l));
        size_t nl = (size_t)(colon - l);
        const char *vp = colon + 1, *ve = lf - 1;
        trim(&vp, &ve);
        if (name_is(l, nl, "transfer-encoding")) {
            te = true;
            const char *last = vp;
            for (const char *s = vp; s < ve; s++)
                if (*s == ',') last = s + 1;
            const char *a = last, *b = ve;
            trim(&a, &b);
            te_last_chunked = (b - a == 7 && !strncasecmp(a, "chunked", 7));
            if (last != vp) px->te_other = true;   // other codings before chunked
        } else if (name_is(l, nl, "content-length")) {
            // accept repeated identical values, reject anything else (RFC 9112 6.3 rule 5)
            for (const char *s = vp; s < ve;) {
                const char *c = memchr(s, ',', (size_t)(ve - s));
                if (!c) c = ve;
                const char *a = s, *b = c;
                trim(&a, &b);
                if (a == b || b - a > 18) return -1;
                uint64_t v = 0;
                for (const char *d = a; d < b; d++) {
                    if ((unsigned)(*d - '0') > 9) return -1;
                    v = v * 10 + (uint64_t)(*d - '0');
                }
                if (cl && v != clv) return -1;
                cl = true;
                clv = v;
                s = c + 1;
            }
        }
        l = lf + 1;
    }
    if (te) return te_last_chunked ? BM_CHUNKED : BM_CLOSE;
    if (cl) {
        *len = clv;
        return BM_LEN;
    }
    return BM_CLOSE;
}

// Forward a response head (1xx or final) to the client with our version and
// without hop-by-hop fields.
static void forward_head(struct proxy *px, const char *p, const char *hdrs, const char *end, int mode, bool final) {
    struct outq *q = &px->c->out;
    const char *sl_end = memchr(p, '\r', (size_t)(end - p));
    out_add(q, "HTTP/1.1", 8);
    out_add(q, p + 8, (size_t)(sl_end - (p + 8)));   // " 200 OK"
    out_add(q, "\r\n", 2);
    struct toks t;
    connection_tokens(hdrs, end, &t);
    for (const char *l = hdrs; !(l[0] == '\r' && l[1] == '\n');) {
        const char *lf = memchr(l, '\n', (size_t)(end - l));
        size_t nl = (size_t)((const char *)memchr(l, ':', (size_t)(lf - l)) - l);
        bool skip = hop_by_hop(l, nl, &t);
        // a chunked body forwarded as is keeps its Transfer-Encoding (with any other codings)
        if (final && mode == BM_CHUNKED && !px->dechunk && name_is(l, nl, "transfer-encoding")) skip = false;
        // Content-Length stays with Content-Length framing and on bodiless responses;
        // it is dropped when the body is chunked or delimited by close
        if (name_is(l, nl, "content-length") && (mode == BM_CHUNKED || mode == BM_CLOSE)) skip = true;
        if (!skip) out_add(q, l, (size_t)(lf + 1 - l));
        l = lf + 1;
    }
    if (final) {
        if (px->close_client)
            out_add(q, "Connection: close\r\n", 19);
        else if (px->ka)
            out_add(q, "Connection: keep-alive\r\n", 24);
    }
    out_add(q, "\r\n", 2);
}

// Parse response heads in rbuf. Returns false if the exchange ended.
static bool response_head(struct proxy *px) {
    for (;;) {
        const char *p = px->rbuf + px->rpos, *end = px->rbuf + px->rlen;
        const char *he = http_scan_head(p, end);
        if (!he) {
            if (px->rlen - px->rpos >= UP_RCAP - 1024 || px->eof) {
                fail(px, 502);   // too large, or the upstream closed early
                return false;
            }
            return true;
        }
        if (he == (const char *)1 || he - p < 13 || memcmp(p, "HTTP/1.", 7) || (unsigned)(p[7] - '0') > 9 ||
            p[8] != ' ' || (unsigned)(p[9] - '0') > 9 || (unsigned)(p[10] - '0') > 9 ||
            (unsigned)(p[11] - '0') > 9 || (p[12] != ' ' && p[12] != '\r')) {
            fail(px, 502);
            return false;
        }
        int status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
        if (status < 100) {
            fail(px, 502);
            return false;
        }
        const char *hdrs = (const char *)memchr(p, '\n', (size_t)(he - p)) + 1;
        // header lines must be well-formed: name ':' value, no obs-fold
        for (const char *l = hdrs; !(l[0] == '\r' && l[1] == '\n');) {
            const char *lf = memchr(l, '\n', (size_t)(he - l));
            const char *colon = memchr(l, ':', (size_t)(lf - l));
            if (!colon || colon == l || *l == ' ' || *l == '\t' || colon[-1] == ' ' || colon[-1] == '\t') {
                fail(px, 502);
                return false;
            }
            l = lf + 1;
        }
        px->rpos = (size_t)(he - px->rbuf);
        if (status / 100 == 1) {
            if (status == 101) {   // we never forward Upgrade, so this is a protocol error
                fail(px, 502);
                return false;
            }
            if (px->v11) forward_head(px, p, hdrs, he, BM_NONE, false);   // never to HTTP/1.0 clients
            continue;
        }
        uint64_t len = 0;
        int mode = response_framing(px, status, hdrs, he, &len);
        if (mode < 0) {
            fail(px, 502);
            return false;
        }
        if (mode == BM_CHUNKED && !px->v11) px->dechunk = true;
        if (px->dechunk && px->te_other) {   // cannot be undone for an HTTP/1.0 client
            fail(px, 502);
            return false;
        }
        // the client connection can only continue if the response length is known
        // and the request body was fully read
        if (mode == BM_CLOSE || px->dechunk || !px->reqdone) px->close_client = true;
        framer_init(&px->resf, mode, len);
        forward_head(px, p, hdrs, he, mode, true);
        px->c->out.responses++;
        px->headdone = px->sent = true;
        if (mode == BM_NONE) px->resdone = true;
        return true;
    }
}

static void response_body(struct proxy *px) {
    struct outq *q = &px->c->out;
    const char *p = px->rbuf + px->rpos, *end = px->rbuf + px->rlen;
    while (p < end && !px->resdone) {
        const char *start = p, *span;
        size_t n;
        int st = framer_step(&px->resf, &p, end, px->dechunk ? &span : NULL, &n);
        if (px->dechunk)
            out_add(q, span, n);
        else
            out_add(q, start, (size_t)(p - start));   // forwarded as received
        if (st == FS_DONE) px->resdone = true;
        if (st == FS_ERR) {
            px->rpos = px->rlen;
            fail(px, 502);
            return;
        }
    }
    px->rpos = (size_t)(p - px->rbuf);
}

void proxy_pump(struct proxy *px) {
    struct conn *c = px->c;
    if (!px->connected) return;

    // client -> upstream: request body bytes, framed as received
    while (!px->reqdone && px->slen < UP_SCAP && c->inpos < c->inlen) {
        const char *p = c->in + c->inpos, *start = p;
        const char *end = p + (c->inlen - c->inpos);
        if ((size_t)(end - p) > UP_SCAP - px->slen) end = p + (UP_SCAP - px->slen);
        int st = framer_step(&px->reqf, &p, end, NULL, NULL);
        sb_add(px, start, (size_t)(p - start));
        c->inpos += (size_t)(p - start);
        if (st == FS_DONE) px->reqdone = true;
        if (st == FS_ERR) {
            fail(px, 400);
            return;
        }
        if (p == start) break;
    }
    if (!px->reqdone && c->eof && c->inpos == c->inlen) {   // the client left mid-body
        proxy_abort(px);
        return;
    }
    while (px->soff < px->slen) {
        ssize_t n = send(px->fd, px->sbuf + px->soff, px->slen - px->soff, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) break;
            if (!px->headdone) {   // the upstream may have answered and closed: read that first
                px->soff = px->slen;
                break;
            }
            px->soff = px->slen;
            break;
        }
        px->soff += (size_t)n;
        px->last = c->w->now;
    }
    if (px->soff == px->slen) px->soff = px->slen = 0;

    // upstream -> client, as fast as the client takes it
    px->throttled = false;
    while (!px->resdone && !px->eof && px->rlen < UP_RCAP) {
        if (c->out.pending >= OUT_HIGH) {
            px->throttled = true;
            break;
        }
        ssize_t n = recv(px->fd, px->rbuf + px->rlen, UP_RCAP - px->rlen, 0);
        if (n > 0) {
            px->rlen += (size_t)n;
            px->last = c->w->now;
        } else if (n == 0) {
            px->eof = true;
        } else {
            if (errno == EAGAIN || errno == EINTR) break;
            px->eof = true;   // reset: handled like a close
        }
        if (!px->headdone && !response_head(px)) return;
        if (px->headdone) response_body(px);
        if (!c->px) return;   // failed
        if (px->rpos == px->rlen) px->rpos = px->rlen = 0;
    }
    if (!px->headdone && px->eof) {
        if (!response_head(px)) return;
    }
    if (px->headdone && !px->resdone && px->eof) {
        if (px->resf.mode == BM_CLOSE)
            px->resdone = true;
        else {   // truncated
            fail(px, 502);
            return;
        }
    }
    if (px->rpos && px->rpos < px->rlen) {
        memmove(px->rbuf, px->rbuf + px->rpos, px->rlen - px->rpos);
        px->rlen -= px->rpos;
        px->rpos = 0;
    }
    if (px->resdone) {
        finish(px);
        return;
    }
    uint32_t want = 0;
    if (px->slen) want |= EPOLLOUT;
    if (!px->eof && c->out.pending < OUT_HIGH && px->rlen < UP_RCAP) want |= EPOLLIN;
    ep_set(c->w, px->fd, px, &px->events, want);
}

void proxy_event(struct proxy *px, uint32_t events) {
    struct conn *c = px->c;
    if (!px->connected) {
        int err = 0;
        socklen_t len = sizeof err;
        if (!(events & (EPOLLOUT | EPOLLERR | EPOLLHUP))) return;
        if (getsockopt(px->fd, SOL_SOCKET, SO_ERROR, &err, &len) || err) {
            fail(px, 502);
            conn_process(c);
            return;
        }
        px->connected = true;
        px->last = c->w->now;
    }
    conn_process(c);
}

void proxy_sweep(struct proxy *px, int64_t now) {
    if (now - px->last > cfg.to_upstream) {
        struct conn *c = px->c;
        fail(px, 504);
        conn_process(c);
    }
}
