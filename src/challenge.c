// JS challenge against request floods.
//
// A client without a valid clearance cookie gets a small page whose script
// finds a counter n such that SHA-256(nonce || n) starts with `difficulty`
// zero bits, stores "nonce||n" in the absurd_pow cookie and reloads. The
// server checks that solution with one hash and answers with a 307 back to the
// same URL that sets absurd_clearance. Everything is stateless:
//
//   nonce     = hex32(ts) || hex64(MAC(ip, ts, "pow")) || hex8(difficulty)   (26 chars)
//   clearance = hex32(expiry) || hex64(MAC(ip, expiry, "clr"))              (24 chars)
//
// MAC is SipHash-2-4 under a random per-process key, so tokens are bound to
// the client's IPv4 address and cannot be forged; they stop being valid when
// the server restarts.
#include "absurd.h"

#include <stdio.h>
#include <string.h>

enum { NONCE_LEN = 26, CLR_LEN = 24, POW_WINDOW = 300 };

static uint64_t mac(uint32_t ip, uint32_t t, uint32_t tag) {
    uint32_t m[3] = {ip, t, tag};
    return siphash24(g_key, m, sizeof m);
}

static bool hexn(const char *p, int n, uint64_t *out) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++) {
        int c = p[i], d;
        if ((unsigned)(c - '0') <= 9)
            d = c - '0';
        else if ((unsigned)(c - 'a') <= 5)
            d = c - 'a' + 10;
        else
            return false;
        v = v << 4 | (uint64_t)d;
    }
    *out = v;
    return true;
}

static bool clearance_ok(const struct span *s, uint32_t ip, int64_t now) {
    uint64_t exp, m;
    if (!s->p || s->e - s->p != CLR_LEN || !hexn(s->p, 8, &exp) || !hexn(s->p + 8, 16, &m)) return false;
    return (int64_t)exp > now && m == mac(ip, (uint32_t)exp, 0x636c72);
}

static bool pow_ok(const struct span *s, uint32_t ip, int64_t now) {
    uint64_t ts, m, bits;
    size_t n = s->p ? (size_t)(s->e - s->p) : 0;
    if (n <= NONCE_LEN || n > NONCE_LEN + 12) return false;
    if (!hexn(s->p, 8, &ts) || !hexn(s->p + 8, 16, &m) || !hexn(s->p + 24, 2, &bits)) return false;
    for (const char *c = s->p + NONCE_LEN; c < s->e; c++)
        if ((unsigned)(*c - '0') > 9) return false;
    if ((int)bits != cfg.ch_bits || (int64_t)ts > now + 5 || now - (int64_t)ts > POW_WINDOW) return false;
    if (m != mac(ip, (uint32_t)ts, 0x706f77)) return false;
    uint8_t h[32];
    sha256(s->p, n, h);
    uint32_t top = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
    return cfg.ch_bits == 32 ? top == 0 : (top >> (32 - cfg.ch_bits)) == 0;
}

int challenge_check(const struct span *clearance, const struct span *pow, uint32_t peer, int64_t now) {
    if (clearance_ok(clearance, peer, now)) return 0;
    if (pow_ok(pow, peer, now)) return 2;
    return 1;
}

static const char page1[] =
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<meta name=\"robots\" content=\"noindex,nofollow\"><title>One moment</title>"
    "<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;"
    "justify-content:center;background:#fafafa;color:#222}main{max-width:32em;padding:1em}"
    "@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head><body><main>"
    "<h1>Checking your browser</h1><p>This site is protected against automated traffic. "
    "The page continues on its own in a moment.</p><noscript><p><b>JavaScript and cookies are required to "
    "continue.</b></p></noscript></main><script>(function(){var C=\"";
static const char page2[] =
    "\",B=parseInt(C.slice(24),16),z=32-B,n=0,K=[1116352408,1899447441,3049323471,3921009573,961987163,"
    "1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,"
    "2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,"
    "1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,"
    "666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,"
    "2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,"
    "659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,"
    "2361852424,2428436474,2756734187,3204031479,3329325298];"
    "function H(s){var h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,"
    "1541459225],m=[],w=[],l=s.length,q=((l+8)>>6<<4)+16,i,j,a,b,c,d,e,f,g,k,t,u;"
    "for(i=0;i<q;i++)m[i]=0;for(i=0;i<l;i++)m[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);"
    "m[l>>2]|=128<<(24-(l&3)*8);m[q-1]=l*8;"
    "for(i=0;i<q;i+=16){a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];k=h[7];"
    "for(j=0;j<64;j++){if(j<16)w[j]=m[i+j];else{t=w[j-15];u=w[j-2];w[j]=((t>>>7|t<<25)^(t>>>18|t<<14)^t>>>3)"
    "+w[j-7]+((u>>>17|u<<15)^(u>>>19|u<<13)^u>>>10)+w[j-16]|0}"
    "t=k+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+(e&f^~e&g)+K[j]+w[j]|0;"
    "u=((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+(a&b^a&c^b&c)|0;"
    "k=g;g=f;f=e;e=d+t|0;d=c;c=b;b=a;a=t+u|0}"
    "h[0]=h[0]+a|0;h[1]=h[1]+b|0;h[2]=h[2]+c|0;h[3]=h[3]+d|0;h[4]=h[4]+e|0;h[5]=h[5]+f|0;h[6]=h[6]+g|0;"
    "h[7]=h[7]+k|0}return h}"
    "function r(){for(var i=0;i<20000;i++,n++)if(H(C+n)[0]>>>z==0){document.cookie=\"absurd_pow=\"+C+n+"
    "\"; path=/; max-age=300; samesite=lax\";location.reload();return}setTimeout(r,0)}r()})();"
    "</script></body></html>\n";

void challenge_page(struct outq *q, struct worker *w, bool close, bool ka, bool nobody, uint32_t peer) {
    out_printf(q,
               "HTTP/1.1 403 Forbidden\r\nServer: absurd\r\nContent-Type: text/html; charset=utf-8\r\n"
               "Content-Length: %zu\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
               "X-Frame-Options: DENY\r\n",
               sizeof page1 - 1 + NONCE_LEN + sizeof page2 - 1);
    http_end_head(q, w, close, ka);
    if (nobody) return;
    uint32_t ts = (uint32_t)w->now;
    char nonce[NONCE_LEN + 1];
    snprintf(nonce, sizeof nonce, "%08x%016llx%02x", ts, (unsigned long long)mac(peer, ts, 0x706f77), cfg.ch_bits);
    out_ref(q, page1, sizeof page1 - 1);
    out_add(q, nonce, NONCE_LEN);
    out_ref(q, page2, sizeof page2 - 1);
}

void challenge_pass(struct outq *q, struct worker *w, bool close, bool ka, uint32_t peer, const struct span *target,
                    bool tls) {
    uint32_t exp = (uint32_t)(w->now + cfg.ch_ttl);
    out_printf(q,
               "HTTP/1.1 307 Temporary Redirect\r\nServer: absurd\r\nLocation: %.*s\r\nCache-Control: no-store\r\n"
               "Content-Length: 0\r\nSet-Cookie: absurd_pow=; Path=/; Max-Age=0\r\n"
               "Set-Cookie: absurd_clearance=%08x%016llx; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s\r\n",
               (int)(target->e - target->p), target->p, exp, (unsigned long long)mac(peer, exp, 0x636c72),
               cfg.ch_ttl, tls ? "; Secure" : "");
    http_end_head(q, w, close, ka);
}
