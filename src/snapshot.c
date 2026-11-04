// Document-root snapshot. Every regular file is read into one arena at
// startup, with its response head pre-rendered, and indexed in a seeded hash
// table; the arena is then made read-only. Requests never touch the
// filesystem, so only paths in the table exist.
#include "absurd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    TABLE_SLOTS = 1 << 17,
    MAX_ENTRIES = TABLE_SLOTS / 2,
    MAXDEPTH = 24,
    URLMAX = 3800,
};
#define SNAP_MAX (1ULL << 30)
#define ARENA_RESERVE (SNAP_MAX + (size_t)MAX_ENTRIES * 2048 + (size_t)TABLE_SLOTS * sizeof(struct entry *))

size_t snap_files, snap_bytes, snap_skipped;
static size_t nentries;
static struct entry **table;
static char *arena, *cur, *arena_end;

static void *alloc(size_t n) {
    char *p = (char *)(((uintptr_t)cur + 15) & ~(uintptr_t)15);
    if (p + n > arena_end) fatal("snapshot arena exhausted");
    cur = p + n;
    return p;
}

static char *astrdup(const char *s, size_t n) {
    char *p = alloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static uint64_t hash(const char *p, size_t n) {
    const uint64_t k = 0x9e3779b97f4a7c15ULL;
    uint64_t h = g_seed ^ (n * k);
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h *= k;
        h ^= h >> 29;
    }
    h ^= h >> 32;
    h *= k;
    return h ^ (h >> 29);
}

const struct entry *snapshot_lookup(const char *path, size_t len) {
    uint64_t h = hash(path, len);
    for (size_t i = h & (TABLE_SLOTS - 1);; i = (i + 1) & (TABLE_SLOTS - 1)) {
        const struct entry *e = table[i];
        if (!e) return NULL;
        if (e->hash == h && e->keylen == len && !memcmp(e->key, path, len)) return e;
    }
}

static void insert(struct entry *e) {
    if (nentries >= TABLE_SLOTS - 1024 || snapshot_lookup(e->key, e->keylen)) return;
    e->hash = hash(e->key, e->keylen);
    size_t i = e->hash & (TABLE_SLOTS - 1);
    while (table[i]) i = (i + 1) & (TABLE_SLOTS - 1);
    table[i] = e;
    nentries++;
}

static const char *ctype(const char *name, size_t n) {
    static const char *const map[][2] = {
        {"html", "text/html; charset=utf-8"}, {"htm", "text/html; charset=utf-8"},
        {"css", "text/css; charset=utf-8"}, {"js", "text/javascript; charset=utf-8"},
        {"mjs", "text/javascript; charset=utf-8"}, {"json", "application/json"},
        {"map", "application/json"}, {"webmanifest", "application/manifest+json"},
        {"txt", "text/plain; charset=utf-8"}, {"md", "text/markdown; charset=utf-8"},
        {"csv", "text/csv; charset=utf-8"}, {"xml", "application/xml"}, {"svg", "image/svg+xml"},
        {"png", "image/png"}, {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"gif", "image/gif"},
        {"webp", "image/webp"}, {"avif", "image/avif"}, {"ico", "image/x-icon"}, {"bmp", "image/bmp"},
        {"wasm", "application/wasm"}, {"pdf", "application/pdf"}, {"woff", "font/woff"},
        {"woff2", "font/woff2"}, {"ttf", "font/ttf"}, {"otf", "font/otf"}, {"mp4", "video/mp4"},
        {"webm", "video/webm"}, {"mp3", "audio/mpeg"}, {"ogg", "audio/ogg"}, {"wav", "audio/wav"},
        {"zip", "application/zip"}, {"gz", "application/gzip"},
    };
    const char *dot = NULL;
    for (size_t i = 0; i < n; i++)
        if (name[i] == '.') dot = name + i + 1;
    if (dot)
        for (size_t i = 0; i < sizeof map / sizeof *map; i++)
            if (strlen(map[i][0]) == (size_t)(name + n - dot) && !strncasecmp(dot, map[i][0], (size_t)(name + n - dot)))
                return map[i][1];
    return "application/octet-stream";
}

static char url[URLMAX + 64];
static size_t urllen;

static void add_file(int dirfd, const char *name, size_t nlen) {
    if (nentries >= MAX_ENTRIES - 4) {
        snap_skipped++;
        return;
    }
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
        close(fd);
        return;
    }
    size_t size = (size_t)st.st_size;
    if (snap_bytes + size > SNAP_MAX || cur + size + 8192 > arena_end) {
        snap_skipped++;
        close(fd);
        return;
    }
    char *body = alloc(size + 1);
    size_t got = 0;
    while (got < size) {
        ssize_t r = read(fd, body + got, size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    snap_bytes += got;
    snap_files++;

    struct entry *e = alloc(sizeof *e);
    memset(e, 0, sizeof *e);
    memcpy(url + urllen, name, nlen);
    e->key = astrdup(url, urllen + nlen);
    e->keylen = urllen + nlen;
    e->file = true;
    e->body = body;
    e->bodylen = got;
    e->ctype = ctype(name, nlen);
    // Last-Modified never later than the server's clock (RFC 9110 8.8.2.1)
    e->mtime = st.st_mtime > g_start ? g_start : st.st_mtime;
    fmt_http_date(e->lastmod, e->mtime);
    uint64_t t = (uint64_t)st.st_mtime ^ ((uint64_t)st.st_mtim.tv_nsec << 20);
    t *= 0x9e3779b97f4a7c15ULL;
    t ^= (uint64_t)st.st_ino ^ (((uint64_t)got >> 17) | ((uint64_t)got << 47));
    t *= 0x9e3779b97f4a7c15ULL;
    t ^= t >> 31;
    snprintf(e->etag, sizeof e->etag, "\"%016llx\"", (unsigned long long)t);
    char h[512];
    int n = snprintf(h, sizeof h,
                     "HTTP/1.1 200 OK\r\nServer: absurd\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "ETag: %s\r\nLast-Modified: %s\r\nAccept-Ranges: bytes\r\nX-Content-Type-Options: nosniff\r\n",
                     e->ctype, got, e->etag, e->lastmod);
    e->hdr = astrdup(h, (size_t)n);
    e->hdrlen = (size_t)n;
    insert(e);
}

// "/dir" -> 301 "/dir/". The Location is percent-encoded, so no byte of a
// file name can reach the header raw.
static void add_redirect(size_t len) {
    struct entry *e = alloc(sizeof *e);
    memset(e, 0, sizeof *e);
    e->key = astrdup(url, len);
    e->keylen = len;
    char h[URLMAX * 3 + 256];
    int n = snprintf(h, sizeof h, "HTTP/1.1 301 Moved Permanently\r\nServer: absurd\r\nContent-Length: 0\r\nLocation: ");
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)url[i];
        if ((unsigned)((c | 0x20) - 'a') < 26u || (unsigned)(c - '0') < 10u || strchr("/-._~", c))
            h[n++] = (char)c;
        else
            n += snprintf(h + n, 4, "%%%02X", c);
    }
    n += snprintf(h + n, sizeof h - (size_t)n, "/\r\nX-Content-Type-Options: nosniff\r\n");
    e->hdr = astrdup(h, (size_t)n);
    e->hdrlen = (size_t)n;
    insert(e);
}

// "/dir/" -> the entry of "/dir/index.html"
static void add_alias(size_t len) {
    memcpy(url + len, "index.html", 10);
    const struct entry *idx = snapshot_lookup(url, len + 10);
    if (!idx) return;
    struct entry *e = alloc(sizeof *e);
    *e = *idx;
    e->key = astrdup(url, len);
    e->keylen = len;
    insert(e);
}

static void walk(int dirfd, int depth) {
    DIR *d = fdopendir(dup(dirfd));
    if (!d) return;
    size_t base = urllen;
    struct dirent *de;
    while ((de = readdir(d))) {
        const char *name = de->d_name;
        if (name[0] == '.') continue;   // ".", "..", and every hidden file
        size_t nlen = strlen(name);
        if (base + nlen >= URLMAX) continue;
        int type = de->d_type;
        if (type == DT_UNKNOWN) {
            struct stat st;
            if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW)) continue;
            type = S_ISDIR(st.st_mode) ? DT_DIR : S_ISREG(st.st_mode) ? DT_REG : DT_LNK;
        }
        if (type == DT_REG) {
            add_file(dirfd, name, nlen);
        } else if (type == DT_DIR && depth < MAXDEPTH) {   // symlinks, sockets, devices: never served
            int sub = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub < 0) continue;
            memcpy(url + base, name, nlen);
            add_redirect(base + nlen);
            url[base + nlen] = '/';
            urllen = base + nlen + 1;
            walk(sub, depth + 1);
            add_alias(urllen);
            urllen = base;
            close(sub);
        }
    }
    closedir(d);
}

void snapshot_load(const char *root) {
    arena = mmap(NULL, ARENA_RESERVE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (arena == MAP_FAILED) die("mmap");
    table = (struct entry **)arena;
    cur = arena + (size_t)TABLE_SLOTS * sizeof(struct entry *);
    arena_end = arena + ARENA_RESERVE;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) fatal("cannot open document root %s: %s", root, strerror(errno));
    url[0] = '/';
    urllen = 1;
    walk(fd, 0);
    add_alias(1);   // "/" -> "/index.html"
    close(fd);
    if (mprotect(arena, ARENA_RESERVE, PROT_READ)) die("mprotect");
}
