// HTTP/1.1 request parsing and responses (RFC 9110, RFC 9112).
#include "absurd.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

// ---------------------------------------------------------------- character classes
enum { C_TCHAR = 1, C_PATH = 2, C_QUERY = 4, C_HOST = 8 };
static unsigned char cls[256];

__attribute__((constructor)) static void init_classes(void) {
    const char *alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (const char *p = alnum; *p; p++) cls[(unsigned char)*p] |= C_TCHAR | C_PATH | C_QUERY | C_HOST;
    for (const char *p = "!#$%&'*+-.^_`|~"; *p; p++) cls[(unsigned char)*p] |= C_TCHAR;
    // pchar without pct-encoded: unreserved / sub-delims / ":" / "@" (and "/" between segments)
    for (const char *p = "-._~!$&'()*+,;=:@/"; *p; p++) cls[(unsigned char)*p] |= C_PATH | C_QUERY;
    cls['?'] |= C_QUERY;
    for (const char *p = "-._~!$&'()*+,;=:[]%"; *p; p++) cls[(unsigned char)*p] |= C_HOST;
}

static int hexv(int c) {
    if ((unsigned)(c - '0') <= 9) return c - '0';
    c |= 0x20;
    if ((unsigned)(c - 'a') <= 5) return c - 'a' + 10;
    return -1;
}

static bool span_ieq(const char *p, const char *e, const char *lit) {
    size_t n = strlen(lit);
    return (size_t)(e - p) == n && !strncasecmp(p, lit, n);
}

static void trim(const char **p, const char **e) {
    while (*p < *e && (**p == ' ' || **p == '\t')) (*p)++;
    while (*e > *p && ((*e)[-1] == ' ' || (*e)[-1] == '\t')) (*e)--;
}

// is lit (lowercase) an element of the comma-separated token list [p, e)?
bool http_has_token(const char *p, const char *e, const char *lit) {
    while (p < e) {
        const char *q = memchr(p, ',', (size_t)(e - p));
        if (!q) q = e;
        const char *a = p, *b = q;
        trim(&a, &b);
        if (span_ieq(a, b, lit)) return true;
        p = q + 1;
    }
    return false;
}

const char *status_text(int s) {
    switch (s) {
    case 100: return "Continue";
    case 200: return "OK";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 412: return "Precondition Failed";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 416: return "Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    }
    return "Unknown";
}

// ---------------------------------------------------------------- head scanning
// Returns the byte after the CRLF CRLF that ends the head, NULL if incomplete,
// or (const char *)1 if the bytes are not valid HTTP: control characters other
// than HTAB, DEL, CR not followed by LF, LF not preceded by CR.
// Bytes that need a closer look: < 0x20 (CTL, HTAB, CR, LF) and DEL. special()
// returns a mask with one bit (x86) or one nibble (arm64) per byte of a 16-byte
// block; everything else is accepted 16 bytes at a time.
#if defined(__SSE2__)
#include <emmintrin.h>
enum { STRIDE = 1 };
static inline uint64_t special(const char *q) {
    __m128i v = _mm_loadu_si128((const __m128i *)q);
    __m128i ctl = _mm_cmpeq_epi8(_mm_min_epu8(v, _mm_set1_epi8(0x1f)), v);
    __m128i del = _mm_cmpeq_epi8(v, _mm_set1_epi8(0x7f));
    return (uint64_t)_mm_movemask_epi8(_mm_or_si128(ctl, del));
}
#elif defined(__aarch64__)
#include <arm_neon.h>
enum { STRIDE = 4 };
static inline uint64_t special(const char *q) {
    uint8x16_t v = vld1q_u8((const uint8_t *)q);
    uint8x16_t m = vorrq_u8(vcleq_u8(v, vdupq_n_u8(0x1f)), vceqq_u8(v, vdupq_n_u8(0x7f)));
    return vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);
}
#else
enum { STRIDE = 1 };
static inline uint64_t special(const char *q) {
    uint64_t m = 0;
    for (int i = 0; i < 16; i++)
        if ((unsigned char)q[i] < 0x20 || q[i] == 0x7f) m |= 1ull << i;
    return m;
}
#endif

// Returns the byte after the CRLF CRLF that ends the head, NULL if incomplete,
// or (const char *)1 if the bytes are not valid HTTP: control characters other
// than HTAB, DEL, CR not followed by LF, LF not preceded by CR.
const char *http_scan_head(const char *p, const char *end) {
    const char *q = p;
    for (;;) {
        uint64_t m;
        int n;
        if (end - q >= 16) {
            m = special(q);
            n = 16;
        } else if (q < end) {
            m = 0;
            n = (int)(end - q);
            for (int i = 0; i < n; i++)
                if ((unsigned char)q[i] < 0x20 || q[i] == 0x7f) m |= 1ull << (i * STRIDE);
        } else {
            return NULL;
        }
        while (m) {
            int i = __builtin_ctzll(m) / STRIDE;
            m &= ~(((1ull << STRIDE) - 1) << (i * STRIDE));
            const char *c = q + i;
            if (*c == '\t') continue;
            if (*c == '\r') {
                if (c + 1 < end && c[1] != '\n') return (const char *)1;
                continue;
            }
            if (*c == '\n') {
                if (c == p || c[-1] != '\r') return (const char *)1;
                if (c - p >= 3 && c[-2] == '\n' && c[-3] == '\r') return c + 1;
                continue;
            }
            return (const char *)1;
        }
        q += n;
    }
}

// ---------------------------------------------------------------- validators
// Does the entity-tag list [p, e) contain our tag? Weak comparison ignores W/;
// strong comparison never matches a weak tag (RFC 9110 8.8.3.2).
static bool etag_match(const char *p, const char *e, const char *tag, bool strong) {
    size_t tl = strlen(tag);
    while (p < e) {
        while (p < e && (*p == ' ' || *p == '\t' || *p == ',')) p++;
        if (p == e) break;
        bool weak = false;
        if (e - p >= 2 && p[0] == 'W' && p[1] == '/') {
            weak = true;
            p += 2;
        }
        if (p == e || *p != '"') return false;   // malformed: no match
        const char *q = memchr(p + 1, '"', (size_t)(e - p - 1));
        if (!q) return false;
        if ((size_t)(q + 1 - p) == tl && !memcmp(p, tag, tl) && !(strong && weak)) return true;
        p = q + 1;
    }
    return false;
}

static bool is_star(struct span s) {
    return s.e - s.p == 1 && *s.p == '*';
}

// Range: bytes=first-[last] | bytes=-suffix. 0: ignore, 1: satisfiable, 2: unsatisfiable.
// Several ranges are ignored (the whole representation is sent, RFC 9110 14.2).
static int parse_range(struct span v, uint64_t size, uint64_t *first, uint64_t *last) {
    const char *p = v.p, *e = v.e;
    if (e - p < 6 || strncasecmp(p, "bytes=", 6)) return 0;
    p += 6;
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    uint64_t a = 0, b = UINT64_MAX;
    bool suffix = false;
    int digits = 0;
    if (p < e && *p == '-') {
        suffix = true;
        p++;
    }
    while (p < e && (unsigned)(*p - '0') <= 9) {
        if (++digits > 18) return 0;
        a = a * 10 + (uint64_t)(*p++ - '0');
    }
    if (!digits) return 0;
    if (!suffix) {
        if (p == e || *p != '-') return 0;
        p++;
        if (p < e && (unsigned)(*p - '0') <= 9) {
            b = 0;
            digits = 0;
            while (p < e && (unsigned)(*p - '0') <= 9) {
                if (++digits > 18) return 0;
                b = b * 10 + (uint64_t)(*p++ - '0');
            }
            if (b < a) return 0;   // invalid range-spec: the header is ignored
        }
    }
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    if (p != e) return 0;   // a list of ranges, or junk
    if (suffix) {
        if (a == 0 || size == 0) return 2;
        *first = size - (a < size ? a : size);
        *last = size - 1;
        return 1;
    }
    if (a >= size) return 2;
    *first = a;
    *last = b < size - 1 ? b : size - 1;
    return 1;
}

static bool has_dot_segment(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != '/') continue;
        size_t j = i + 1;
        if (j < n && p[j] == '.') {
            j++;
            if (j == n || p[j] == '/') return true;
            if (p[j] == '.' && (j + 1 == n || p[j + 1] == '/')) return true;
        }
    }
    return false;
}

static bool prefix_match(const char *path, size_t n, const char *pre, size_t pl) {
    return pl <= n && !memcmp(path, pre, pl);
}

// ---------------------------------------------------------------- the parser
static const char *const methods[] = {NULL, "GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"};
static const unsigned char mlen[] = {0, 3, 4, 7, 4, 3, 6, 5, 5, 7};

#define FAIL(code)              \
    do {                        \
        r->kind = K_STATUS;     \
        r->status = (code);     \
        r->close = true;        \
        r->bmode = BM_NONE;     \
        return head_end;        \
    } while (0)

const char *http_parse(struct worker *w, const char *p, const char *end, uint32_t peer, bool tls,
                       struct request *r) {
    (void)tls;
    memset(r, 0, offsetof(struct request, tgtbuf));
    while (end - p >= 2 && p[0] == '\r' && p[1] == '\n') p += 2;   // empty lines before a request
    const char *head_end = http_scan_head(p, end);
    if (!head_end) return NULL;
    if (head_end == (const char *)1) {
        head_end = end;   // unparseable: consume everything and close
        FAIL(400);
    }
    if (head_end - p > HEADMAX) FAIL(431);
    r->end = head_end;

    // ---- request-line = method SP request-target SP HTTP-version CRLF
    const char *q = p;
    while (cls[(unsigned char)*q] & C_TCHAR) q++;
    if (q == p || *q != ' ') FAIL(400);
    r->mth = (struct span){p, q};
    r->method = MT_UNKNOWN;
    for (int i = 1; i <= MT_CONNECT; i++)
        if ((size_t)(q - p) == mlen[i] && !memcmp(p, methods[i], mlen[i])) {
            r->method = i;
            break;
        }
    const char *t0 = q + 1, *t1 = t0;
    while ((unsigned char)*t1 > 0x20 && (unsigned char)*t1 < 0x7f) t1++;
    if (t1 == t0 || *t1 != ' ') FAIL(400);   // HTAB, raw non-ASCII, missing version
    const char *v = t1 + 1;
    if (memcmp(v, "HTTP/", 5) || (unsigned)(v[5] - '0') > 9 || v[6] != '.' || (unsigned)(v[7] - '0') > 9 ||
        v[8] != '\r' || v[9] != '\n')
        FAIL(400);
    if (v[5] != '1') FAIL(505);
    r->v11 = v[7] != '0';   // HTTP/1.1 and higher minor versions are handled as 1.1
    r->hdrs = v + 10;
    if (t1 - t0 > PATHMAX) FAIL(414);
    if (r->method == MT_CONNECT) FAIL(405);

    // ---- request-target forms (RFC 9112 3.2)
    bool aster = false;
    if (*t0 == '/') {
        r->target = (struct span){t0, t1};
    } else if (*t0 == '*' && t1 - t0 == 1) {
        if (r->method != MT_OPTIONS) FAIL(400);
        aster = true;
        r->target = (struct span){t0, t1};
    } else {
        size_t sl = (t1 - t0 >= 7 && !strncasecmp(t0, "http://", 7))    ? 7
                    : (t1 - t0 >= 8 && !strncasecmp(t0, "https://", 8)) ? 8
                                                                         : 0;
        if (!sl) FAIL(400);
        const char *a = t0 + sl, *ae = a;
        while (ae < t1 && *ae != '/' && *ae != '?') {
            if (!(cls[(unsigned char)*ae] & C_HOST)) FAIL(400);   // no userinfo, no junk
            ae++;
        }
        if (ae == a) FAIL(400);
        r->auth = (struct span){a, ae};
        r->absform = true;
        if (ae < t1 && *ae == '/') {
            r->target = (struct span){ae, t1};
        } else {   // empty path: "/" + query
            r->tgtbuf[0] = '/';
            memcpy(r->tgtbuf + 1, ae, (size_t)(t1 - ae));
            r->target = (struct span){r->tgtbuf, r->tgtbuf + 1 + (t1 - ae)};
        }
    }

    // ---- validate the target, percent-decode the path
    size_t plen = 0;
    if (aster) {
        w->path[plen++] = '*';
    } else {
        bool query = false;
        for (const char *s = r->target.p; s < r->target.e; s++) {
            unsigned char c = (unsigned char)*s;
            if (c == '%') {
                if (r->target.e - s < 3) FAIL(400);
                int hi = hexv(s[1]), lo = hexv(s[2]);
                if (hi < 0 || lo < 0) FAIL(400);
                s += 2;
                if (!query) {
                    if (!(hi | lo)) FAIL(400);   // %00
                    w->path[plen++] = (char)(hi << 4 | lo);
                }
            } else if (query) {
                if (!(cls[c] & C_QUERY)) FAIL(400);
            } else if (c == '?') {
                query = true;
            } else {
                if (!(cls[c] & C_PATH)) FAIL(400);   // '#', '"', '<', '\', ...
                w->path[plen++] = (char)c;
            }
        }
    }

    // ---- header fields
    struct span inm = {0}, im = {0}, ims = {0}, ius = {0}, ir = {0}, range = {0}, clr = {0}, pow = {0};
    bool cl_seen = false, te_seen = false, te_chunked = false, te_last = false, te_other = false;
    bool expect_bad = false, cclose = false, cka = false;
    for (const char *l = r->hdrs; !(l[0] == '\r' && l[1] == '\n');) {
        const char *lf = memchr(l, '\n', (size_t)(head_end - l));
        if (*l == ' ' || *l == '\t') FAIL(400);   // obs-fold
        const char *n = l;
        while (cls[(unsigned char)*n] & C_TCHAR) n++;
        if (n == l || *n != ':') FAIL(400);       // empty name, whitespace before ':', junk
        size_t nl = (size_t)(n - l);
        const char *vp = n + 1, *ve = lf - 1;
        trim(&vp, &ve);
        struct span val = {vp, ve};
#define NAME(s) (nl == sizeof(s) - 1 && !strncasecmp(l, s, nl))
        if (NAME("host")) {
            if (r->host) FAIL(400);
            r->host = true;
            for (const char *s = vp; s < ve; s++)
                if (!(cls[(unsigned char)*s] & C_HOST)) FAIL(400);
        } else if (NAME("connection")) {
            cclose |= http_has_token(vp, ve, "close");
            cka |= http_has_token(vp, ve, "keep-alive");
        } else if (NAME("content-length")) {
            if (cl_seen || vp == ve || ve - vp > 18) FAIL(ve - vp > 18 ? 413 : 400);
            cl_seen = true;
            uint64_t len = 0;
            for (const char *s = vp; s < ve; s++) {
                if ((unsigned)(*s - '0') > 9) FAIL(400);   // "+0", "1, 1", lists
                len = len * 10 + (uint64_t)(*s - '0');
            }
            r->blen = len;
        } else if (NAME("transfer-encoding")) {
            te_seen = true;
            for (const char *s = vp; s < ve;) {
                const char *c = memchr(s, ',', (size_t)(ve - s));
                if (!c) c = ve;
                const char *a = s, *b = c;
                trim(&a, &b);
                if (a < b) {
                    if (span_ieq(a, b, "chunked")) {
                        if (te_chunked) FAIL(400);   // chunked applied twice
                        te_chunked = te_last = true;
                    } else {
                        te_other = true;
                        te_last = false;
                    }
                }
                s = c + 1;
            }
        } else if (NAME("expect")) {
            if (span_ieq(vp, ve, "100-continue"))
                r->expect = true;
            else
                expect_bad = true;
        } else if (NAME("cookie")) {
            for (const char *s = vp; s < ve;) {
                const char *c = memchr(s, ';', (size_t)(ve - s));
                if (!c) c = ve;
                const char *a = s, *b = c;
                trim(&a, &b);
                const char *eq = memchr(a, '=', (size_t)(b - a));
                if (eq) {
                    if (eq - a == 16 && !memcmp(a, "absurd_clearance", 16)) clr = (struct span){eq + 1, b};
                    if (eq - a == 10 && !memcmp(a, "absurd_pow", 10)) pow = (struct span){eq + 1, b};
                }
                s = c + 1;
            }
        } else if (NAME("if-none-match")) {
            if (!inm.p) inm = val;
        } else if (NAME("if-match")) {
            if (!im.p) im = val;
        } else if (NAME("if-modified-since")) {
            if (!ims.p) ims = val;
        } else if (NAME("if-unmodified-since")) {
            if (!ius.p) ius = val;
        } else if (NAME("if-range")) {
            if (!ir.p) ir = val;
        } else if (NAME("range")) {
            if (!range.p) range = val;
        }
#undef NAME
        l = lf + 1;
    }

    if (r->v11 && !r->host) FAIL(400);   // HTTP/1.1 requires Host
    // ---- message body framing (RFC 9112 6.3)
    if (te_seen) {
        if (!r->v11) FAIL(400);          // Transfer-Encoding in HTTP/1.0: faulty framing
        if (!te_last) FAIL(400);         // chunked not final: the length is unknowable
        if (cl_seen) FAIL(400);          // both: a smuggling attempt
        if (te_other) FAIL(501);         // codings we cannot decode
        r->bmode = BM_CHUNKED;
    } else if (r->blen) {
        r->bmode = BM_LEN;
    }
    if (expect_bad) FAIL(417);
    // ---- persistence (RFC 9112 9.3)
    if (r->v11)
        r->close = cclose;
    else if (!cclose && cka)
        r->ka = true;
    else
        r->close = true;
    r->nobody = r->method == MT_HEAD;

    // ---- routing
    if (aster) {
        r->kind = K_OPTIONS;
        goto static_body;
    }
    for (int i = 0; i < cfg.nchal; i++)
        if (prefix_match(w->path, plen, cfg.chal[i], cfg.challen[i])) {
            int c = challenge_check(&clr, &pow, peer, w->now);
            if (c == 1) {
                r->kind = K_CHPAGE;
                goto static_body;
            }
            if (c == 2) {
                r->kind = K_CHPASS;
                goto static_body;
            }
            break;
        }
    for (int i = 0; i < cfg.nroutes; i++)
        if (prefix_match(w->path, plen, cfg.routes[i].prefix, cfg.routes[i].plen)) {
            if (has_dot_segment(w->path, plen)) FAIL(400);   // never let "/api/../x" reach the upstream
            r->rt = &cfg.routes[i];
            r->kind = K_PROXY;
            return head_end;
        }
    switch (r->method) {
    case MT_GET:
    case MT_HEAD:
        break;
    case MT_OPTIONS:
        r->kind = K_OPTIONS;
        goto static_body;
    case MT_UNKNOWN:
        r->kind = K_STATUS;
        r->status = 501;
        goto static_body;
    default:   // POST, PUT, DELETE, PATCH, TRACE on static files
        r->kind = K_STATUS;
        r->status = 405;
        goto static_body;
    }
    const struct entry *e = snapshot_lookup(w->path, plen);
    if (!e) {
        r->kind = K_STATUS;
        r->status = 404;
        goto static_body;
    }
    r->ent = e;
    if (!e->file) {
        r->kind = K_REDIRECT;
        goto static_body;
    }
    r->kind = K_FILE;

    // ---- preconditions, in the order of RFC 9110 13.2.2
    int64_t t;
    if (im.p) {
        if (!is_star(im) && !etag_match(im.p, im.e, e->etag, true)) goto fail412;
    } else if (ius.p && parse_http_date(ius.p, ius.e, &t) && e->mtime > t) {
        goto fail412;
    }
    if (inm.p) {
        if (is_star(inm) || etag_match(inm.p, inm.e, e->etag, false)) goto not_modified;
    } else if (ims.p && parse_http_date(ims.p, ims.e, &t) && e->mtime <= t) {
        goto not_modified;
    }
    // ---- Range, for GET only (RFC 9110 14.2)
    if (range.p && r->method == MT_GET) {
        bool ok = true;
        if (ir.p) {
            if (*ir.p == '"' || (ir.e - ir.p >= 2 && ir.p[0] == 'W' && ir.p[1] == '/'))   // an entity-tag: ours, strongly
                ok = (size_t)(ir.e - ir.p) == strlen(e->etag) && !memcmp(ir.p, e->etag, strlen(e->etag));
            else   // a date: must be exactly Last-Modified
                ok = parse_http_date(ir.p, ir.e, &t) && t == e->mtime;
        }
        if (ok) {
            int rr = parse_range(range, e->bodylen, &r->rfirst, &r->rlast);
            if (rr == 1) r->kind = K_RANGE;
            if (rr == 2) r->kind = K_416;
        }
    }
    goto static_body;
fail412:
    r->kind = K_STATUS;
    r->status = 412;
    goto static_body;
not_modified:
    r->kind = K_304;
    r->nobody = true;

static_body:
    // We answer this request ourselves. A body is skipped before the next request;
    // a client waiting for 100 Continue never gets one, so it gets the final
    // response and the connection is closed.
    if (r->bmode != BM_NONE) {
        if (r->expect) r->close = true;
        if (r->bmode == BM_LEN && r->blen > cfg.max_body) {
            r->kind = K_STATUS;
            r->status = 413;
            r->close = true;
        }
    }
    return head_end;
}

// ---------------------------------------------------------------- responses
void http_end_head(struct outq *q, struct worker *w, bool close, bool ka) {
    int v = close ? 1 : ka ? 2 : 0;
    out_ref(q, w->date[v], w->datelen[v]);
}

// A short text/plain response. Returns whether the connection must close.
bool http_status(struct outq *q, struct worker *w, int status, bool close, bool nobody) {
    const char *txt = status_text(status);
    // these come from a broken request, or leave the stream in an unknown state
    if (status == 400 || status == 408 || status == 413 || status == 414 || status == 417 || status == 431 ||
        status == 501 || status == 502 || status == 503 || status == 504 || status == 505)
        close = true;
    int blen = (int)strlen(txt) + 5;
    out_printf(q,
               "HTTP/1.1 %d %s\r\nServer: absurd\r\nContent-Type: text/plain; charset=utf-8\r\n"
               "Content-Length: %d\r\n%sX-Content-Type-Options: nosniff\r\n",
               status, txt, blen, status == 405 ? "Allow: GET, HEAD, OPTIONS\r\n" : "");
    http_end_head(q, w, close, false);
    if (!nobody) out_printf(q, "%d %s\n", status, txt);
    return close;
}

void http_respond(struct conn *c, struct request *r) {
    struct outq *q = &c->out;
    struct worker *w = c->w;
    const struct entry *e = r->ent;
    bool close = r->close;
    switch (r->kind) {
    case K_FILE:
        out_ref(q, e->hdr, e->hdrlen);
        http_end_head(q, w, close, r->ka);
        if (!r->nobody) out_ref(q, e->body, e->bodylen);
        break;
    case K_REDIRECT:
        out_ref(q, e->hdr, e->hdrlen);
        http_end_head(q, w, close, r->ka);
        break;
    case K_304:
        // 304 carries the validators (ETag) and Date; no representation metadata (RFC 9110 15.4.5)
        out_printf(q, "HTTP/1.1 304 Not Modified\r\nServer: absurd\r\nETag: %s\r\n", e->etag);
        http_end_head(q, w, close, r->ka);
        break;
    case K_RANGE: {
        uint64_t n = r->rlast - r->rfirst + 1;
        out_printf(q,
                   "HTTP/1.1 206 Partial Content\r\nServer: absurd\r\nContent-Type: %s\r\n"
                   "Content-Range: bytes %llu-%llu/%zu\r\nContent-Length: %llu\r\nETag: %s\r\n"
                   "Last-Modified: %s\r\nAccept-Ranges: bytes\r\nX-Content-Type-Options: nosniff\r\n",
                   e->ctype, (unsigned long long)r->rfirst, (unsigned long long)r->rlast, e->bodylen,
                   (unsigned long long)n, e->etag, e->lastmod);
        http_end_head(q, w, close, r->ka);
        if (!r->nobody) out_ref(q, e->body + r->rfirst, n);
        break;
    }
    case K_416:
        out_printf(q,
                   "HTTP/1.1 416 Range Not Satisfiable\r\nServer: absurd\r\nContent-Range: bytes */%zu\r\n"
                   "Content-Length: 0\r\nX-Content-Type-Options: nosniff\r\n",
                   e->bodylen);
        http_end_head(q, w, close, r->ka);
        break;
    case K_OPTIONS:
        out_add(q, "HTTP/1.1 204 No Content\r\nServer: absurd\r\nAllow: GET, HEAD, OPTIONS\r\n", 68);
        http_end_head(q, w, close, r->ka);
        break;
    case K_CHPAGE:
        challenge_page(q, w, close, r->ka, r->nobody, c->peer);
        break;
    case K_CHPASS:
        challenge_pass(q, w, close, r->ka, c->peer, &r->target, c->ls->tls);
        break;
    case K_STATUS:
    default:
        close = http_status(q, w, r->status, close, r->nobody);
        break;
    }
    q->responses++;
    if (close) c->drain = true;
}
