// absurd -- a sandboxed static-file server and reverse proxy.
#ifndef ABSURD_H
#define ABSURD_H

#define _GNU_SOURCE
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <time.h>

#ifndef NO_TLS
#include <openssl/ssl.h>
#else
typedef struct ssl_st SSL;
#endif

// ---------------------------------------------------------------- limits
enum {
    MAX_THREADS = 256,
    MAX_LISTEN = 8,
    MAX_ROUTES = 32,
    MAX_CHAL = 32,
    INCAP = 32768,           // request bytes buffered per connection
    HEADMAX = 16384,         // largest request head (431 above)
    PATHMAX = 2048,          // longest request target (414 above)
    UP_RCAP = 65536,         // upstream receive buffer
    UP_SCAP = 65536,         // upstream send buffer
    OUT_HIGH = 256 * 1024,   // stop producing output for a connection above this
    MAX_PIPELINE = 64,       // queued responses per connection before reading pauses
};

// ---------------------------------------------------------------- configuration
struct listener_cfg {
    uint32_t addr;           // network order
    uint16_t port;
    bool tls;
};

struct route {
    char *prefix;
    size_t plen;
    struct sockaddr_in addr;
    char *host;              // "ip:port", for Host when the client sent none
};

struct config {
    struct listener_cfg listen[MAX_LISTEN];
    int nlisten;
    int threads;
    const char *root;
    struct route routes[MAX_ROUTES];
    int nroutes;
    char *chal[MAX_CHAL];
    size_t challen[MAX_CHAL];
    int nchal;
    int ch_bits;             // proof-of-work difficulty (leading zero bits)
    int ch_ttl;              // clearance cookie lifetime (s)
    int to_header, to_idle, to_send, to_upstream;
    size_t max_body;         // largest request body skipped for static targets
    const char *tls_cert, *tls_key;
};

extern struct config cfg;
void config_defaults(void);
void config_load(const char *path);

// ---------------------------------------------------------------- snapshot
struct entry {
    const char *key;
    size_t keylen;
    uint64_t hash;
    bool file;               // false: a "/dir" -> "/dir/" redirect
    const char *hdr;         // 200 head (or 301 head), without Date and the final CRLF
    size_t hdrlen;
    const char *ctype;
    const char *body;
    size_t bodylen;
    int64_t mtime;
    char etag[19];           // "<16 hex>"
    char lastmod[30];
};

void snapshot_load(const char *root);
const struct entry *snapshot_lookup(const char *path, size_t len);
extern size_t snap_files, snap_bytes, snap_skipped;

// ---------------------------------------------------------------- helpers
extern uint64_t g_seed;
extern uint8_t g_key[16];
extern int64_t g_start;
void fmt_http_date(char out[30], int64_t t);
bool parse_http_date(const char *p, const char *end, int64_t *out);
uint64_t siphash24(const uint8_t key[16], const void *data, size_t len);
void sha256(const void *data, size_t len, uint8_t out[32]);
_Noreturn void die(const char *what);
_Noreturn void fatal(const char *fmt, ...);

// ---------------------------------------------------------------- body framing
enum { BM_NONE, BM_LEN, BM_CHUNKED, BM_CLOSE };
enum { FS_MORE, FS_DONE, FS_ERR };

struct framer {
    uint8_t mode, state;
    uint16_t line;
    uint64_t rem;
};

// Consume framed body bytes from [*p, end). Returns FS_MORE, FS_DONE or FS_ERR;
// *p advances past what was consumed. If span/spanlen are given, they receive the
// next run of payload bytes (chunk data), and the function returns after it.
int framer_step(struct framer *f, const char **p, const char *end, const char **span, size_t *spanlen);
void framer_init(struct framer *f, int mode, uint64_t len);

// ---------------------------------------------------------------- output queue
struct seg {
    const char *p;           // static data (snapshot), or NULL: bytes at buf + off
    size_t off, len;
};

struct outq {
    struct seg *segs;
    size_t nseg, cap, head, done;
    char *buf;
    size_t blen, bcap;
    size_t pending;          // bytes not yet written
    size_t responses;        // responses queued since the queue was last empty
};

void out_add(struct outq *q, const void *p, size_t len);
void out_ref(struct outq *q, const void *p, size_t len);
void out_printf(struct outq *q, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void out_free(struct outq *q);

// ---------------------------------------------------------------- connections
enum { EV_LISTEN = 1, EV_CONN, EV_UPSTREAM };

struct worker;
struct proxy;

struct conn {
    int type;                // EV_CONN
    int fd;
    struct worker *w;
    const struct listener_cfg *ls;
    SSL *ssl;
    bool handshaking;
    uint32_t peer;           // IPv4, network order
    char *in;
    size_t inpos, inlen;
    struct outq out;
    bool eof, drain, closing, partial, discarding, lingering;
    int64_t linger_since;
    struct framer body;      // a request body we skip
    int64_t last, rstart;
    struct proxy *px;
    uint32_t events;
    struct conn *prev, *next;
};

struct proxy {
    int type;                // EV_UPSTREAM
    int fd;
    struct conn *c;
    const struct route *rt;
    bool connected, reqdone, headdone, resdone, eof;
    bool head_method, dechunk, close_client, sent, v11, ka, te_other, throttled;
    struct framer reqf, resf;
    char *sbuf;              // bytes for the upstream
    size_t soff, slen;
    char *rbuf;              // bytes from the upstream
    size_t rpos, rlen;
    int64_t last;
    uint32_t events;
};

struct listener {
    int type;                // EV_LISTEN
    int fd;
    const struct listener_cfg *cfg;
    uint32_t events;
};

struct worker {
    int id, ep;
    struct listener ls[MAX_LISTEN];
    struct conn *conns;      // all live connections, for the timeout sweep
    int64_t now;
    // the Date line and the end of the head, in three variants (plain, close,
    // keep-alive). Responses reference these bytes; they change once a second,
    // always to a valid line of the same length.
    char date[3][80];
    size_t datelen[3];
    char path[PATHMAX + 16]; // decoded request path
    bool accept_paused;
    void **dead;             // objects closed during this batch of events, freed after it
    size_t ndead, deadcap;
};

void worker_bury(struct worker *w, void *obj);

void worker_run(struct worker *w);

// ---------------------------------------------------------------- HTTP
enum {
    MT_UNKNOWN, MT_GET, MT_HEAD, MT_OPTIONS, MT_POST, MT_PUT, MT_DELETE, MT_PATCH, MT_TRACE, MT_CONNECT,
};

enum { K_STATUS, K_FILE, K_304, K_RANGE, K_416, K_OPTIONS, K_CHPAGE, K_CHPASS, K_PROXY, K_REDIRECT };

struct span {
    const char *p, *e;
};

struct request {
    int kind, status;        // status for K_STATUS
    int method;
    bool v11, close, ka, nobody, expect, absform, host;
    const struct entry *ent;
    const struct route *rt;
    uint64_t rfirst, rlast;
    struct span mth, target; // target: origin-form (path + query)
    const char *hdrs, *end;  // header lines, end of head
    struct span auth;        // authority of an absolute-form target
    int bmode;
    uint64_t blen;
    char tgtbuf[PATHMAX + 2];
};

// Parse one request head from [p, end). Returns the end of the head, or NULL
// if it is incomplete. Errors are reported as K_STATUS with close set.
const char *http_parse(struct worker *w, const char *p, const char *end, uint32_t peer, bool tls,
                       struct request *r);
void http_respond(struct conn *c, struct request *r);
bool http_status(struct outq *q, struct worker *w, int status, bool close, bool nobody);
const char *status_text(int status);
const char *http_scan_head(const char *p, const char *end);
bool http_has_token(const char *p, const char *e, const char *lit);
void http_end_head(struct outq *q, struct worker *w, bool close, bool ka);

// ---------------------------------------------------------------- proxy
void proxy_start(struct conn *c, struct request *r);
void proxy_event(struct proxy *px, uint32_t events);
void proxy_pump(struct proxy *px);
void proxy_abort(struct proxy *px);
void proxy_sweep(struct proxy *px, int64_t now);

// ---------------------------------------------------------------- JS challenge
// 0: cleared, 1: serve the challenge page, 2: just solved, redirect with a cookie
int challenge_check(const struct span *clearance, const struct span *pow, uint32_t peer, int64_t now);
void challenge_page(struct outq *q, struct worker *w, bool close, bool ka, bool nobody, uint32_t peer);
void challenge_pass(struct outq *q, struct worker *w, bool close, bool ka, uint32_t peer, const struct span *target, bool tls);

// ---------------------------------------------------------------- TLS
void atls_init(void);
SSL *atls_new(int fd);
void atls_free(SSL *ssl);
// >0 bytes, 0 EOF, -1 would block, -2 error
ssize_t atls_read(SSL *ssl, void *buf, size_t len);
ssize_t atls_write(SSL *ssl, const void *buf, size_t len);
int atls_handshake(SSL *ssl);   // 1 done, 0 in progress, -1 failed
bool atls_wants_write(SSL *ssl);

// ---------------------------------------------------------------- server glue
void conn_update(struct conn *c);
void conn_process(struct conn *c);
void conn_close(struct conn *c);
void ep_set(struct worker *w, int fd, void *ptr, uint32_t *cur, uint32_t want);
void sandbox(void);

#endif
