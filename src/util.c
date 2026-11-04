// Dates, hashes, body framing and the output queue.
#include "absurd.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint64_t g_seed;
uint8_t g_key[16];
int64_t g_start;

_Noreturn void die(const char *what) {
    fprintf(stderr, "absurd: fatal: %s failed: %s\n", what, strerror(errno));
    exit(1);
}

_Noreturn void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("absurd: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(2);
}

// ---------------------------------------------------------------- dates
static const char days[] = "SunMonTueWedThuFriSat";
static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

// days since 1970-01-01 <-> civil date (H. Hinnant's algorithms)
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int64_t)yoe + era * 400 + (*m <= 2);
}

// IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
void fmt_http_date(char out[30], int64_t t) {
    int64_t dn = t >= 0 ? t / 86400 : (t - 86399) / 86400, y;
    int64_t s = t - dn * 86400;
    unsigned m, d;
    civil_from_days(dn, &y, &m, &d);
    int wd = (int)(((dn % 7) + 11) % 7);   // 1970-01-01 was a Thursday
    char tmp[64];
    snprintf(tmp, sizeof tmp, "%.3s, %02u %.3s %04d %02d:%02d:%02d GMT", days + wd * 3, d % 100, months + (m - 1) * 3,
             (int)(y % 10000), (int)(s / 3600), (int)(s / 60 % 60), (int)(s % 60));
    memcpy(out, tmp, 29);
    out[29] = 0;
}

static bool two(const char **p, const char *end, int *v) {
    if (end - *p < 2 || (unsigned)((*p)[0] - '0') > 9 || (unsigned)((*p)[1] - '0') > 9) return false;
    *v = ((*p)[0] - '0') * 10 + (*p)[1] - '0';
    *p += 2;
    return true;
}

static bool lit(const char **p, const char *end, const char *s) {
    size_t n = strlen(s);
    if ((size_t)(end - *p) < n || memcmp(*p, s, n)) return false;
    *p += n;
    return true;
}

static bool month(const char **p, const char *end, int *m) {
    if (end - *p < 3) return false;
    for (int i = 0; i < 12; i++)
        if (!memcmp(*p, months + i * 3, 3)) {
            *m = i + 1;
            *p += 3;
            return true;
        }
    return false;
}

static bool hms(const char **p, const char *end, int *h, int *mi, int *s) {
    return two(p, end, h) && lit(p, end, ":") && two(p, end, mi) && lit(p, end, ":") && two(p, end, s) &&
           *h < 24 && *mi < 60 && *s <= 60;
}

// RFC 9110 5.6.7: recipients accept IMF-fixdate, the obsolete RFC 850 format and asctime.
bool parse_http_date(const char *p, const char *end, int64_t *out) {
    int d, m, y, yy, h, mi, s;
    const char *q = p;
    while (q < end && ((*q | 0x20) >= 'a' && (*q | 0x20) <= 'z')) q++;
    if (q - p < 3 || q == end) return false;
    p = q;
    if (*p == ',') {
        p++;
        if (!lit(&p, end, " ") || !two(&p, end, &d)) return false;
        if (p < end && *p == ' ') {          // IMF-fixdate
            p++;
            if (!month(&p, end, &m) || !lit(&p, end, " ") || !two(&p, end, &yy) || !two(&p, end, &y)) return false;
            y += yy * 100;
        } else if (p < end && *p == '-') {   // RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT"
            p++;
            if (!month(&p, end, &m) || !lit(&p, end, "-") || !two(&p, end, &yy)) return false;
            // two-digit years: more than 50 years in the future means the previous century
            int cur = 1970 + (int)(g_start / 31556952);
            y = 2000 + yy;
            if (y > cur + 50) y -= 100;
        } else
            return false;
        if (!lit(&p, end, " ") || !hms(&p, end, &h, &mi, &s) || !lit(&p, end, " GMT") || p != end) return false;
    } else if (*p == ' ') {                  // asctime: "Sun Nov  6 08:49:37 1994"
        p++;
        if (!month(&p, end, &m) || !lit(&p, end, " ")) return false;
        if (p < end && *p == ' ') {
            p++;
            if (p == end || (unsigned)(*p - '0') > 9) return false;
            d = *p++ - '0';
        } else if (!two(&p, end, &d))
            return false;
        if (!lit(&p, end, " ") || !hms(&p, end, &h, &mi, &s) || !lit(&p, end, " ") || !two(&p, end, &yy) ||
            !two(&p, end, &y) || p != end)
            return false;
        y += yy * 100;
    } else
        return false;
    if (d < 1 || d > 31 || y < 1900) return false;
    *out = days_from_civil(y, (unsigned)m, (unsigned)d) * 86400 + h * 3600 + mi * 60 + s;
    return true;
}

// ---------------------------------------------------------------- SipHash-2-4
#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                                                      \
    do {                                                                                              \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);                                     \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                                                        \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                                                        \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);                                     \
    } while (0)

static uint64_t le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

uint64_t siphash24(const uint8_t key[16], const void *data, size_t len) {
    const uint8_t *in = data;
    uint64_t k0 = le64(key), k1 = le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    size_t i;
    for (i = 0; i + 8 <= len; i += 8) {
        uint64_t m = le64(in + i);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    for (size_t j = 0; i + j < len; j++) b |= (uint64_t)in[i + j] << (8 * j);
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

// ---------------------------------------------------------------- SHA-256
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void sha256(const void *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const uint8_t *p = data;
    size_t n = len;
    for (; n >= 64; n -= 64, p += 64) sha256_block(h, p);
    uint8_t blk[128] = {0};
    memcpy(blk, p, n);
    blk[n] = 0x80;
    size_t tot = n + 9 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blk[tot - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha256_block(h, blk);
    if (tot == 128) sha256_block(h, blk + 64);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
}

// ---------------------------------------------------------------- body framing (RFC 9112 6, 7)
enum {
    CS_SIZE0, CS_SIZE, CS_EXT, CS_SIZELF, CS_DATA, CS_DATACR, CS_DATALF,
    CS_TRL0, CS_TRL, CS_TRLLF, CS_ENDLF, CS_DONE,
};
#define LINE_MAX_ 4096

void framer_init(struct framer *f, int mode, uint64_t len) {
    f->mode = (uint8_t)mode;
    f->state = CS_SIZE0;
    f->line = 0;
    f->rem = len;
}

static int hexv(int c) {
    if ((unsigned)(c - '0') <= 9) return c - '0';
    c |= 0x20;
    if ((unsigned)(c - 'a') <= 5) return c - 'a' + 10;
    return -1;
}

int framer_step(struct framer *f, const char **pp, const char *end, const char **span, size_t *spanlen) {
    const char *p = *pp;
    if (span) *spanlen = 0;
    switch (f->mode) {
    case BM_NONE:
        return FS_DONE;
    case BM_CLOSE:
        if (span) {
            *span = p;
            *spanlen = (size_t)(end - p);
        }
        *pp = end;
        return FS_MORE;
    case BM_LEN: {
        size_t n = (size_t)(end - p);
        if (n > f->rem) n = (size_t)f->rem;
        if (span) {
            *span = p;
            *spanlen = n;
        }
        f->rem -= n;
        *pp = p + n;
        return f->rem ? FS_MORE : FS_DONE;
    }
    }
    // chunked
    while (p < end) {
        unsigned char c = (unsigned char)*p;
        switch (f->state) {
        case CS_SIZE0:
        case CS_SIZE: {
            int v = hexv(c);
            if (v >= 0) {
                if (f->rem >> 56) return FS_ERR;   // chunk too large
                f->rem = f->rem << 4 | (unsigned)v;
                f->state = CS_SIZE;
            } else if (f->state == CS_SIZE && (c == ';' || c == ' ' || c == '\t')) {
                f->state = CS_EXT;
                f->line = 0;
            } else if (f->state == CS_SIZE && c == '\r')
                f->state = CS_SIZELF;
            else
                return FS_ERR;
            p++;
            break;
        }
        case CS_EXT:   // chunk extensions are ignored, but must be plain text
            if (c == '\r')
                f->state = CS_SIZELF;
            else if ((c < 0x20 && c != '\t') || c == 0x7f || ++f->line > LINE_MAX_)
                return FS_ERR;
            p++;
            break;
        case CS_SIZELF:
            if (c != '\n') return FS_ERR;
            f->state = f->rem ? CS_DATA : CS_TRL0;
            p++;
            break;
        case CS_DATA: {
            size_t n = (size_t)(end - p);
            if (n > f->rem) n = (size_t)f->rem;
            f->rem -= n;
            if (!f->rem) f->state = CS_DATACR;
            if (span) {
                *span = p;
                *spanlen = n;
                *pp = p + n;
                return FS_MORE;
            }
            p += n;
            break;
        }
        case CS_DATACR:
            if (c != '\r') return FS_ERR;
            f->state = CS_DATALF;
            p++;
            break;
        case CS_DATALF:
            if (c != '\n') return FS_ERR;
            f->state = CS_SIZE0;
            p++;
            break;
        case CS_TRL0:
            if (c == '\r')
                f->state = CS_ENDLF;
            else if (c < 0x20 || c == 0x7f || c == ' ')   // no obs-fold, no CTL
                return FS_ERR;
            else {
                f->state = CS_TRL;
                f->line = 1;
            }
            p++;
            break;
        case CS_TRL:
            if (c == '\r')
                f->state = CS_TRLLF;
            else if ((c < 0x20 && c != '\t') || c == 0x7f || ++f->line > LINE_MAX_)
                return FS_ERR;
            p++;
            break;
        case CS_TRLLF:
            if (c != '\n') return FS_ERR;
            f->state = CS_TRL0;
            p++;
            break;
        case CS_ENDLF:
            if (c != '\n') return FS_ERR;
            f->state = CS_DONE;
            *pp = p + 1;
            return FS_DONE;
        case CS_DONE:
            *pp = p;
            return FS_DONE;
        }
    }
    *pp = p;
    return f->state == CS_DONE ? FS_DONE : FS_MORE;
}

// ---------------------------------------------------------------- output queue
static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("realloc");
    return q;
}

static struct seg *seg_new(struct outq *q) {
    if (q->nseg == q->cap) {
        q->cap = q->cap ? q->cap * 2 : 16;
        q->segs = xrealloc(q->segs, q->cap * sizeof *q->segs);
    }
    return &q->segs[q->nseg++];
}

void out_add(struct outq *q, const void *p, size_t len) {
    if (!len) return;
    if (q->blen + len > q->bcap) {
        size_t cap = q->bcap ? q->bcap : 4096;
        while (cap < q->blen + len) cap *= 2;
        q->buf = xrealloc(q->buf, cap);
        q->bcap = cap;
    }
    memcpy(q->buf + q->blen, p, len);
    struct seg *last = q->nseg > q->head ? &q->segs[q->nseg - 1] : NULL;
    if (last && !last->p && last->off + last->len == q->blen)
        last->len += len;   // contiguous with the previous owned segment
    else {
        struct seg *s = seg_new(q);
        s->p = NULL;
        s->off = q->blen;
        s->len = len;
    }
    q->blen += len;
    q->pending += len;
}

void out_ref(struct outq *q, const void *p, size_t len) {
    if (!len) return;
    // Small pieces are cheaper copied: pipelined responses then leave as one
    // contiguous buffer instead of many tiny iovecs. Large bodies stay by reference.
    if (len < 1024) {
        out_add(q, p, len);
        return;
    }
    struct seg *s = seg_new(q);
    s->p = p;
    s->off = 0;
    s->len = len;
    q->pending += len;
}

void out_printf(struct outq *q, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) {
        out_add(q, tmp, (size_t)n);
        return;
    }
    char *big = malloc((size_t)n + 1);
    if (!big) die("malloc");
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    out_add(q, big, (size_t)n);
    free(big);
}

void out_free(struct outq *q) {
    free(q->segs);
    free(q->buf);
    memset(q, 0, sizeof *q);
}
