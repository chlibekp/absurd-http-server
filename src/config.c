// Configuration file: one directive per line, arguments separated by blanks,
// '#' starts a comment. See absurd.conf.example.
#include "absurd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config cfg;

void config_defaults(void) {
    memset(&cfg, 0, sizeof cfg);
    cfg.root = ".";
    cfg.ch_bits = 16;
    cfg.ch_ttl = 3600;
    cfg.to_header = 15;
    cfg.to_idle = 30;
    cfg.to_send = 60;
    cfg.to_upstream = 60;
    cfg.max_body = 1 << 20;
}

static const char *cfg_file;
static int cfg_line;

_Noreturn static void bad(const char *msg) {
    fatal("%s:%d: %s", cfg_file, cfg_line, msg);
}

static long num(const char *s, long lo, long hi) {
    char *e;
    errno = 0;
    long v = strtol(s, &e, 10);
    if (!*s || *e || errno || v < lo || v > hi) bad("bad number");
    return v;
}

// "a.b.c.d:port", or a bare port when allow_port is set
static bool parse_addr(const char *s, uint32_t *addr, uint16_t *port, bool allow_port) {
    const char *colon = strrchr(s, ':');
    char host[64];
    if (!colon) {
        if (!allow_port) return false;
        *addr = 0;
        colon = s - 1;
    } else {
        size_t n = (size_t)(colon - s);
        if (n == 0 || n >= sizeof host) return false;
        memcpy(host, s, n);
        host[n] = 0;
        struct in_addr a;
        if (inet_pton(AF_INET, host, &a) != 1) return false;
        *addr = a.s_addr;
    }
    char *e;
    long p = strtol(colon + 1, &e, 10);
    if (!colon[1] || *e || p < 1 || p > 65535) return false;
    *port = (uint16_t)p;
    return true;
}

static void add_listen(int n, char **a) {
    if (n < 2 || n > 3) bad("usage: listen [ADDR:]PORT [tls]");
    if (cfg.nlisten == MAX_LISTEN) bad("too many listen directives");
    struct listener_cfg *l = &cfg.listen[cfg.nlisten];
    if (!parse_addr(a[1], &l->addr, &l->port, true)) bad("bad address (want [IPv4:]port)");
    l->tls = false;
    if (n == 3) {
        if (strcmp(a[2], "tls")) bad("unknown listen option");
        l->tls = true;
    }
    cfg.nlisten++;
}

void config_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) fatal("cannot open config %s: %s", path, strerror(errno));
    cfg_file = path;
    cfg_line = 0;
    bool listened = false;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) >= 0) {
        cfg_line++;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char *a[8];
        int n = 0;
        for (char *t = strtok(line, " \t\r\n"); t; t = strtok(NULL, " \t\r\n")) {
            if (n == 8) bad("too many arguments");
            a[n++] = strdup(t);   // kept for the life of the process
        }
        if (!n) continue;
        const char *d = a[0];
        if (!strcmp(d, "listen")) {
            if (!listened) cfg.nlisten = 0;   // the file replaces the default listener
            listened = true;
            add_listen(n, a);
        } else if (n != 2 && strcmp(d, "proxy")) {
            bad("wrong number of arguments");
        } else if (!strcmp(d, "threads")) {
            cfg.threads = (int)num(a[1], 1, MAX_THREADS);
        } else if (!strcmp(d, "root")) {
            cfg.root = a[1];
        } else if (!strcmp(d, "proxy")) {
            if (n != 3) bad("usage: proxy PREFIX IPv4:PORT");
            if (a[1][0] != '/') bad("prefix must start with /");
            if (cfg.nroutes == MAX_ROUTES) bad("too many proxy routes");
            struct route *r = &cfg.routes[cfg.nroutes];
            uint32_t addr;
            uint16_t port;
            if (!parse_addr(a[2], &addr, &port, false) || !addr) bad("bad upstream (want IPv4:port)");
            r->prefix = a[1];
            r->plen = strlen(a[1]);
            r->addr.sin_family = AF_INET;
            r->addr.sin_addr.s_addr = addr;
            r->addr.sin_port = htons(port);
            r->host = a[2];
            cfg.nroutes++;
        } else if (!strcmp(d, "challenge")) {
            if (a[1][0] != '/') bad("prefix must start with /");
            if (cfg.nchal == MAX_CHAL) bad("too many challenge prefixes");
            cfg.chal[cfg.nchal] = a[1];
            cfg.challen[cfg.nchal++] = strlen(a[1]);
        } else if (!strcmp(d, "challenge_difficulty")) {
            cfg.ch_bits = (int)num(a[1], 1, 32);
        } else if (!strcmp(d, "challenge_ttl")) {
            cfg.ch_ttl = (int)num(a[1], 60, 365L * 86400);
        } else if (!strcmp(d, "header_timeout")) {
            cfg.to_header = (int)num(a[1], 1, 86400);
        } else if (!strcmp(d, "idle_timeout")) {
            cfg.to_idle = (int)num(a[1], 1, 86400);
        } else if (!strcmp(d, "send_timeout")) {
            cfg.to_send = (int)num(a[1], 1, 86400);
        } else if (!strcmp(d, "upstream_timeout")) {
            cfg.to_upstream = (int)num(a[1], 1, 86400);
        } else if (!strcmp(d, "max_body")) {
            cfg.max_body = (size_t)num(a[1], 0, 1L << 40);
        } else if (!strcmp(d, "tls_cert")) {
            cfg.tls_cert = a[1];
        } else if (!strcmp(d, "tls_key")) {
            cfg.tls_key = a[1];
        } else {
            bad("unknown directive");
        }
    }
    free(line);
    fclose(f);
}
