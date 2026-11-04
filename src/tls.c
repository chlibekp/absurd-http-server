// TLS for "listen ... tls" listeners, through OpenSSL. TLS 1.2 and 1.3, ALPN
// http/1.1. The certificate chain and key are loaded at startup, before
// privileges are dropped, so the key file can be readable by root only.
#include "absurd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef NO_TLS

void atls_init(void) {
    for (int i = 0; i < cfg.nlisten; i++)
        if (cfg.listen[i].tls) fatal("this build has no TLS support (built with NO_TLS)");
}
SSL *atls_new(int fd) { (void)fd; return NULL; }
void atls_free(SSL *ssl) { (void)ssl; }
ssize_t atls_read(SSL *ssl, void *buf, size_t len) { (void)ssl; (void)buf; (void)len; return -2; }
ssize_t atls_write(SSL *ssl, const void *buf, size_t len) { (void)ssl; (void)buf; (void)len; return -2; }
int atls_handshake(SSL *ssl) { (void)ssl; return -1; }
bool atls_wants_write(SSL *ssl) { (void)ssl; return false; }

#else

#include <openssl/err.h>
#include <openssl/rand.h>

static SSL_CTX *ctx;

static int alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    for (unsigned int i = 0; i + 1 <= inlen;) {
        unsigned int n = in[i];
        if (i + 1 + n > inlen) break;
        if (n == 8 && !memcmp(in + i + 1, "http/1.1", 8)) {
            *out = in + i + 1;
            *outlen = 8;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + n;
    }
    return SSL_TLSEXT_ERR_NOACK;   // no HTTP/1.1 offered: carry on without ALPN
}

_Noreturn static void ssl_fatal(const char *what) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
    fatal("TLS: %s: %s", what, buf);
}

void atls_init(void) {
    bool need = false;
    for (int i = 0; i < cfg.nlisten; i++) need |= cfg.listen[i].tls;
    if (!need) return;
    if (!cfg.tls_cert || !cfg.tls_key) fatal("a tls listener needs tls_cert and tls_key");
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) ssl_fatal("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_COMPRESSION |
                                 SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS);
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!SHA1") != 1)
        ssl_fatal("cipher list");
    if (SSL_CTX_use_certificate_chain_file(ctx, cfg.tls_cert) != 1) ssl_fatal(cfg.tls_cert);
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg.tls_key, SSL_FILETYPE_PEM) != 1) ssl_fatal(cfg.tls_key);
    if (SSL_CTX_check_private_key(ctx) != 1) ssl_fatal("certificate and key do not match");
    SSL_CTX_set_alpn_select_cb(ctx, alpn, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    // seed the DRBG now: after the sandbox is up there is no /dev/urandom to fall back to
    unsigned char b[16];
    if (RAND_bytes(b, sizeof b) != 1) ssl_fatal("RAND_bytes");
}

SSL *atls_new(int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    return ssl;
}

void atls_free(SSL *ssl) {
    if (!ssl) return;
    ERR_clear_error();
    SSL_shutdown(ssl);   // best effort close_notify
    SSL_free(ssl);
    ERR_clear_error();
}

static ssize_t result(SSL *ssl, int r) {
    int e = SSL_get_error(ssl, r);
    ERR_clear_error();
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return -1;
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    if (e == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EINTR)) return -1;
    return -2;
}

ssize_t atls_read(SSL *ssl, void *buf, size_t len) {
    ERR_clear_error();
    int r = SSL_read(ssl, buf, len > 1 << 30 ? 1 << 30 : (int)len);
    return r > 0 ? r : result(ssl, r);
}

ssize_t atls_write(SSL *ssl, const void *buf, size_t len) {
    ERR_clear_error();
    int r = SSL_write(ssl, buf, len > 1 << 20 ? 1 << 20 : (int)len);
    return r > 0 ? r : result(ssl, r);
}

int atls_handshake(SSL *ssl) {
    ERR_clear_error();
    int r = SSL_do_handshake(ssl);
    if (r == 1) return 1;
    return result(ssl, r) == -1 ? 0 : -1;
}

bool atls_wants_write(SSL *ssl) {
    return SSL_want_write(ssl);
}

#endif
