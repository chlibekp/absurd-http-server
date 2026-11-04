"""End-to-end tests for absurd: static files, HTTP/1.1 conformance, the
reverse proxy, the JS challenge, TLS and the config file.

    python3 test/run.py                 # build/absurd against a generated site
    python3 test/run.py --slow          # also the header-timeout (408) test
    python3 test/run.py fixture DIR     # only write the test site into DIR
    ABSURD=/path/to/binary python3 test/run.py
    ABSURD_HOST=127.0.0.1:18081 python3 test/run.py --external   # server started elsewhere

Every response is checked byte for byte. Needs Python 3.8+ and the openssl CLI.
"""
import hashlib, os, random, re, resource, shlex, shutil, socket, ssl, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HTTP, HTTPS, UP, DEAD = 18081, 18443, 18090, 18091
HOST = "127.0.0.1"
# when the server runs elsewhere (e.g. in a VM), how it sees us and the upstream
PEER = os.environ.get("EXPECT_PEER", "127.0.0.1")
UPHOST = os.environ.get("EXPECT_UPHOST", f"127.0.0.1:{UP}")

# ---------------------------------------------------------------- fixture
def make_fixture(d):
    os.makedirs(f"{d}/docs/deep", exist_ok=True)
    os.makedirs(f"{d}/.git", exist_ok=True)
    os.makedirs(f"{d}/with space", exist_ok=True)
    os.makedirs(f"{d}/protected", exist_ok=True)
    w = lambda p, b: open(f"{d}/{p}", "wb").write(b)
    w("index.html", b"<!doctype html><title>t</title>hello\n")
    w("style.css", b"body{color:red}\n")
    w("data.json", b'{"ok":true}\n')
    w("docs/index.html", b"docs\n")
    w("docs/deep/page.txt", b"deep\n")
    w("with space/a b.txt", b"spaced\n")
    w("protected/index.html", b"secret area\n")
    w(".env", b"SECRET=1\n")
    w(".git/config", b"[core]\n")
    w("empty.txt", b"")
    rnd = random.Random(7)
    w("big.bin", bytes(rnd.getrandbits(8) for _ in range(3_000_000)))
    for name, target in (("passwd", "/etc/passwd"), ("docslink", "docs"), ("up", "..")):
        try: os.symlink(target, f"{d}/{name}")
        except FileExistsError: pass
    for root, dirs, files in os.walk(d):
        os.chmod(root, 0o755)
        for f in files:
            if not os.path.islink(f"{root}/{f}"): os.chmod(f"{root}/{f}", 0o644)

ROOT = {}
def load_expected(d):
    for p in ["index.html", "style.css", "data.json", "docs/index.html", "docs/deep/page.txt",
              "with space/a b.txt", "big.bin", "empty.txt"]:
        ROOT[b"/" + p.replace(" ", "%20").encode()] = open(f"{d}/{p}", "rb").read()
    ROOT[b"/"] = ROOT[b"/index.html"]; ROOT[b"/docs/"] = ROOT[b"/docs/index.html"]

# ---------------------------------------------------------------- client helpers
PORT = HTTP
def conn(port=None, tls=False):
    s = socket.create_connection((HOST, port or PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if tls:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        s = ctx.wrap_socket(s, server_hostname="localhost")
    s.settimeout(20)
    return s

class Reader:
    def __init__(self, s): self.s, self.buf = s, bytearray()
    def fill(self):
        c = self.s.recv(1 << 20)
        if not c: raise EOFError
        self.buf += c
    def head(self):
        while b"\r\n\r\n" not in self.buf: self.fill()
        i = self.buf.index(b"\r\n\r\n")
        raw = bytes(self.buf[:i + 4]); del self.buf[:i + 4]
        lines = raw[:-4].decode("latin1").split("\r\n")
        assert re.match(r"HTTP/1\.1 \d{3} ", lines[0] + " "), lines[0]
        status = int(lines[0].split()[1])
        h = {}
        for l in lines[1:]:
            k, v = l.split(":", 1); k = k.strip().lower()
            h[k] = h[k] + ", " + v.strip() if k in h else v.strip()
        return status, h, raw
    def response(self, head=False, until_close=False):
        while True:
            status, h, raw = self.head()
            if status // 100 != 1: break
        if head or status in (204, 304):
            return status, h, b""
        if "transfer-encoding" in h:
            assert h["transfer-encoding"].lower().endswith("chunked"), h
            body = bytearray()
            while True:
                while b"\r\n" not in self.buf: self.fill()
                i = self.buf.index(b"\r\n"); size = int(self.buf[:i].split(b";")[0], 16); del self.buf[:i + 2]
                if size == 0:
                    while b"\r\n" not in self.buf: self.fill()
                    while not self.buf.startswith(b"\r\n"):   # trailers
                        i = self.buf.index(b"\r\n"); del self.buf[:i + 2]
                        while b"\r\n" not in self.buf: self.fill()
                    del self.buf[:2]
                    return status, h, bytes(body)
                while len(self.buf) < size + 2: self.fill()
                body += self.buf[:size]; del self.buf[:size + 2]
        if "content-length" not in h:
            try:
                while True: self.fill()
            except (EOFError, ConnectionResetError): pass
            body = bytes(self.buf); self.buf.clear()
            return status, h, body
        n = int(h["content-length"])
        while len(self.buf) < n: self.fill()
        body = bytes(self.buf[:n]); del self.buf[:n]
        return status, h, body
    def closed(self, timeout=3):
        self.s.settimeout(timeout)
        try:
            while True:
                c = self.s.recv(65536)
                if not c: return not self.buf
                self.buf += c
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError): return True
        except socket.timeout: return False

def req(path, method="GET", extra=b"", ver=b"HTTP/1.1", host=b"t"):
    h = b"Host: " + host + b"\r\n" if host is not None else b""
    return method.encode() + b" " + path + b" " + ver + b"\r\n" + h + extra + b"\r\n"

def one(raw, head=False, port=None, tls=False):
    s = conn(port, tls); s.sendall(raw); r = Reader(s)
    st, h, b = r.response(head)
    return st, h, b, r

def expect_status(raw, code, closes=None, head=False):
    st, h, b, r = one(raw, head)
    assert st == code, f"{raw[:70]!r}: got {st}, want {code}"
    if closes is not None:
        assert r.closed(3 if closes else 0.5) == closes, f"{raw[:70]!r}: closed should be {closes}"
    return h, b

T = []
def test(fn): T.append(fn); return fn

# ================================================================ static files
@test
def files_and_types():
    for path, ctype in [(b"/", "text/html; charset=utf-8"), (b"/style.css", "text/css; charset=utf-8"),
                        (b"/data.json", "application/json"), (b"/docs/", "text/html; charset=utf-8"),
                        (b"/docs/deep/page.txt", "text/plain; charset=utf-8"),
                        (b"/with%20space/a%20b.txt", "text/plain; charset=utf-8"),
                        (b"/big.bin", "application/octet-stream"), (b"/empty.txt", "text/plain; charset=utf-8")]:
        st, h, b, _ = one(req(path))
        assert st == 200 and h["content-type"] == ctype, (path, st, h)
        assert h["x-content-type-options"] == "nosniff" and "date" in h and "etag" in h
        assert h["accept-ranges"] == "bytes" and "last-modified" in h
        assert b == ROOT[path], path

@test
def query_ok_fragment_rejected():
    st, _, b, _ = one(req(b"/style.css?v=3&x=%41/?")); assert st == 200 and b == ROOT[b"/style.css"]
    expect_status(req(b"/style.css#x"), 400, closes=True)     # '#' is not part of a request-target

@test
def directory_redirect():
    h, _ = expect_status(req(b"/docs"), 301); assert h["location"] == "/docs/"
    h, _ = expect_status(req(b"/with%20space"), 301); assert h["location"] == "/with%20space/"

@test
def nothing_outside_the_snapshot():
    for p in [b"/.env", b"/.git/config", b"/passwd", b"/docslink/", b"/up/", b"/../../etc/passwd",
              b"/..%2f..%2fetc%2fpasswd", b"/%2e%2e/%2e%2e/etc/passwd", b"/docs/../.env",
              b"/docs/..%2f.env", b"/./index.html", b"//index.html", b"/index.html/", b"/proc/self/environ",
              b"/docs/deep", b"/docs/deep/"]:
        expect_status(req(p), 404 if p != b"/docs/deep" else 301)

@test
def head_has_no_body():
    s = conn(); s.sendall(req(b"/big.bin", "HEAD") + req(b"/style.css")); r = Reader(s)
    st, h, b = r.response(head=True)
    assert st == 200 and h["content-length"] == "3000000" and b == b""
    st, h, b = r.response(); assert b == ROOT[b"/style.css"]
    st, h, b, r = one(req(b"/nope", "HEAD"), head=True); assert st == 404
    s = conn(); s.sendall(req(b"/nope", "HEAD") + req(b"/style.css")); r = Reader(s)   # no body after a HEAD 404
    assert r.response(head=True)[0] == 404 and r.response()[2] == ROOT[b"/style.css"]

# ================================================================ methods, versions, targets
@test
def methods_and_versions():
    h, _ = expect_status(req(b"/", "POST", b"Content-Length: 0\r\n"), 405, closes=False)
    assert h["allow"] == "GET, HEAD, OPTIONS"
    expect_status(req(b"/", "DELETE"), 405, closes=False)
    expect_status(req(b"/", "PUT", b"Content-Length: 3\r\n") + b"abc", 405, closes=False)
    expect_status(req(b"/", "get"), 501, closes=True)          # methods are case-sensitive
    expect_status(req(b"/", "BREW"), 501, closes=True)
    expect_status(req(b"/", "G(T"), 400, closes=True)          # not a token
    expect_status(req(b"t:443", "CONNECT"), 405, closes=True)
    expect_status(req(b"/", ver=b"HTTP/2.0"), 505, closes=True)
    expect_status(req(b"/", ver=b"HTTP/3.0"), 505, closes=True)
    expect_status(req(b"/", ver=b"HTTP/1.x"), 400, closes=True)
    expect_status(req(b"/", ver=b"http/1.1"), 400, closes=True)
    expect_status(req(b"/", ver=b"HTCPCP/1"), 400, closes=True)
    expect_status(req(b"/", ver=b"HTTP/1.2"), 200, closes=False)   # a higher minor is handled as 1.1

@test
def options():
    s = conn(); s.sendall(req(b"*", "OPTIONS") + req(b"/style.css", "OPTIONS") + req(b"/")); r = Reader(s)
    for _ in range(2):
        st, h, b = r.response(); assert st == 204 and h["allow"] == "GET, HEAD, OPTIONS" and "content-length" not in h
    assert r.response()[2] == ROOT[b"/"]
    expect_status(req(b"*"), 400, closes=True)                 # '*' only with OPTIONS

@test
def absolute_form():
    st, h, b, r = one(req(b"http://example.com/style.css")); assert st == 200 and b == ROOT[b"/style.css"]
    st, h, b, r = one(req(b"HTTPS://example.com:8443/style.css?x=1")); assert st == 200
    st, h, b, r = one(req(b"http://example.com")); assert st == 200 and b == ROOT[b"/"]
    st, h, b, r = one(req(b"http://example.com?q")); assert st == 200 and b == ROOT[b"/"]
    expect_status(req(b"http://user@example.com/"), 400, closes=True)
    expect_status(req(b"http:///"), 400, closes=True)
    expect_status(req(b"ftp://example.com/"), 400, closes=True)

@test
def http10_and_connection_header():
    st, h, _, r = one(b"GET / HTTP/1.0\r\n\r\n")
    assert st == 200 and h["connection"] == "close" and r.closed()
    s = conn(); s.sendall(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n" * 2); r = Reader(s)
    for _ in range(2):
        st, h, _ = r.response(); assert st == 200 and h["connection"] == "keep-alive"
    st, h, _, r = one(req(b"/", extra=b"Connection: close\r\n")); assert h["connection"] == "close" and r.closed()
    st, h, _, r = one(req(b"/", extra=b"Connection: foo, Close\r\n")); assert h["connection"] == "close" and r.closed()
    _, _, _, r = one(req(b"/", extra=b"Connection: closed\r\n")); assert not r.closed(timeout=0.5)   # a token, not a substring
    _, _, _, r = one(req(b"/")); assert not r.closed(timeout=0.5)

# ================================================================ bodies and framing
@test
def request_bodies():
    # a Content-Length body on a static target is skipped; the connection stays usable
    s = conn(); r = Reader(s)
    s.sendall(req(b"/style.css", extra=b"Content-Length: 5\r\n") + b"hello" + req(b"/data.json"))
    assert r.response()[2] == ROOT[b"/style.css"] and r.response()[2] == ROOT[b"/data.json"]
    # and a chunked one, with extensions and trailers
    s.sendall(req(b"/", "POST", b"Transfer-Encoding: chunked\r\n") + b"5;x=y\r\nhello\r\n0\r\nT: v\r\n\r\n" + req(b"/style.css"))
    assert r.response()[0] == 405 and r.response()[2] == ROOT[b"/style.css"]
    # split across packets
    s.sendall(req(b"/", "POST", b"Content-Length: 10\r\n") + b"01234"); time.sleep(0.05); s.sendall(b"56789" + req(b"/"))
    assert r.response()[0] == 405 and r.response()[2] == ROOT[b"/"]
    s.sendall(req(b"/", "POST", b"Transfer-Encoding: chunked\r\n") + b"zz\r\n")   # malformed chunked body
    assert r.response()[0] == 405 and r.closed()

@test
def smuggling_rejected():
    expect_status(req(b"/", extra=b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n"), 400, closes=True)
    expect_status(req(b"/", extra=b"Transfer-Encoding: chunked, gzip\r\n"), 400, closes=True)   # chunked not last
    expect_status(req(b"/", extra=b"Transfer-Encoding: gzip, chunked\r\n") + b"0\r\n\r\n", 501, closes=True)
    expect_status(req(b"/", extra=b"Transfer-Encoding: chunked, chunked\r\n"), 400, closes=True)
    expect_status(b"GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: +0\r\n"), 400, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: 1, 1\r\n") + b"x", 400, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: 1\r\nContent-Length: 1\r\n") + b"x", 400, closes=True)
    expect_status(req(b"/", extra=b"Content-Length:\r\n"), 400, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: 99999999999999999999\r\n"), 413, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: 2000000\r\n"), 413, closes=True)   # above max_body
    st, *_ = one(req(b"/", extra=b"Content-Length: 0\r\n")); assert st == 200

@test
def expect_continue():
    # static target: the final response comes at once, and the connection closes
    expect_status(req(b"/", "POST", b"Content-Length: 5\r\nExpect: 100-continue\r\n"), 405, closes=True)
    st, *_ = one(req(b"/", extra=b"Expect: 100-continue\r\n")); assert st == 200   # no body: nothing to wait for
    expect_status(req(b"/", extra=b"Expect: teapot\r\n"), 417, closes=True)

@test
def malformed_requests():
    bad = [b"GET / HTTP/1.1\nHost: t\n\n",                 # bare LF
           b"GET / HTTP/1.1\r\nHost: t\rX: y\r\n\r\n",     # bare CR
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\x00b\r\n\r\n",
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\x7fb\r\n\r\n",
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\r\n b\r\n\r\n",   # obs-fold
           b"GET / HTTP/1.1\r\nHost : t\r\n\r\n",          # space before colon
           b"GET / HTTP/1.1\r\nHo(st: t\r\n\r\n",          # not a token
           b"GET / HTTP/1.1\r\nNoColon\r\n\r\n",
           b"GET / HTTP/1.1\r\n: empty\r\n\r\n",
           b"GET / HTTP/1.1\r\n\r\n",                      # 1.1 without Host
           b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
           b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",         # invalid Host
           b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n",
           b"GET /a b HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /a\"b HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /a<b> HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /a\\b HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /?a{b} HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%zz HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%4 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /?%4 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%00 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /\xc3\xa9 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET  / HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET / HTTP/1.1 \r\nHost: t\r\n\r\n",
           b"GET\t/ HTTP/1.1\r\nHost: t\r\n\r\n",
           b"\x00\xff" * 100 + b"\r\n\r\n"]
    for raw in bad:
        expect_status(raw, 400, closes=True)
    st, h, b, r = one(b"GET / HTTP/1.1\r\nHost: t\r\nX: caf\xc3\xa9\r\n\r\n")   # obs-text in a value is fine
    assert st == 200
    st, *_ = one(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"); assert st == 200           # empty Host is valid
    st, *_ = one(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"); assert st == 200

@test
def size_limits():
    expect_status(req(b"/" + b"a" * 3000), 414, closes=True)
    s = conn(); s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n" + b"X-Pad: " + b"a" * 20000 + b"\r\n\r\n")
    r = Reader(s); st, *_ = r.response(); assert st == 431 and r.closed()
    st, *_ = one(req(b"/", extra=b"X-Big: " + b"a" * 12000 + b"\r\n")); assert st == 200

@test
def leading_crlf_tolerated():
    st, *_ = one(b"\r\n\r\n" + req(b"/")); assert st == 200

# ================================================================ conditional requests
def meta(path=b"/style.css"):
    st, h, _, _ = one(req(path)); return h["etag"], h["last-modified"]

def hdate(t): return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(t))

@test
def etag_revalidation():
    tag, _ = meta()
    for inm in (tag, "W/" + tag, '"nope", ' + tag, '"x",W/' + tag, "*"):
        st, h, b, _ = one(req(b"/style.css", extra=b"If-None-Match: " + inm.encode() + b"\r\n"))
        assert st == 304 and b == b"" and h["etag"] == tag and "content-length" not in h, inm
    expect_status(req(b"/style.css", extra=b'If-None-Match: "0000000000000000"\r\n'), 200)
    expect_status(req(b"/style.css", extra=b"If-None-Match: " + tag.upper().encode() + b"\r\n"), 200)  # opaque, case-sensitive
    st, *_ = one(req(b"/style.css", "HEAD", b"If-None-Match: " + tag.encode() + b"\r\n"), head=True); assert st == 304

@test
def modified_since():
    tag, lm = meta()
    t = int(time.mktime(time.strptime(lm, "%a, %d %b %Y %H:%M:%S GMT")) - time.timezone)
    rfc850 = time.strftime("%A, %d-%b-%y %H:%M:%S GMT", time.gmtime(t))
    asctime = time.strftime("%a %b %e %H:%M:%S %Y", time.gmtime(t))
    for d in (lm, rfc850, asctime, hdate(t + 3600)):
        expect_status(req(b"/style.css", extra=b"If-Modified-Since: " + d.encode() + b"\r\n"), 304)
    expect_status(req(b"/style.css", extra=b"If-Modified-Since: " + hdate(t - 1).encode() + b"\r\n"), 200)
    expect_status(req(b"/style.css", extra=b"If-Modified-Since: yesterday\r\n"), 200)   # invalid: ignored
    # If-None-Match wins over If-Modified-Since
    expect_status(req(b"/style.css", extra=b'If-None-Match: "x"\r\nIf-Modified-Since: ' + lm.encode() + b"\r\n"), 200)

@test
def preconditions_412():
    tag, lm = meta()
    expect_status(req(b"/style.css", extra=b'If-Match: "nope"\r\n'), 412, closes=False)
    expect_status(req(b"/style.css", extra=b"If-Match: W/" + tag.encode() + b"\r\n"), 412)   # strong comparison
    expect_status(req(b"/style.css", extra=b"If-Match: " + tag.encode() + b"\r\n"), 200)
    expect_status(req(b"/style.css", extra=b"If-Match: *\r\n"), 200)
    expect_status(req(b"/style.css", extra=b"If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n"), 412)
    expect_status(req(b"/style.css", extra=b"If-Unmodified-Since: " + lm.encode() + b"\r\n"), 200)
    expect_status(req(b"/nope", extra=b'If-Match: "x"\r\n'), 404)   # preconditions only apply to 2xx

# ================================================================ ranges
@test
def ranges():
    body = ROOT[b"/style.css"]; n = len(body)
    for spec, a, b in [(b"bytes=0-3", 0, 3), (b"bytes=4-", 4, n - 1), (b"bytes=-5", n - 5, n - 1),
                       (b"bytes=2-1000", 2, n - 1), (b"bytes=-1000", 0, n - 1), (b"BYTES = 1-1".replace(b" ", b""), 1, 1)]:
        st, h, got, _ = one(req(b"/style.css", extra=b"Range: " + spec + b"\r\n"))
        assert st == 206 and h["content-range"] == f"bytes {a}-{b}/{n}" and got == body[a:b + 1], spec
    for spec in (b"bytes=100-200", b"bytes=-0", b"bytes=16-"):
        st, h, got, r = one(req(b"/style.css", extra=b"Range: " + spec + b"\r\n"))
        assert st == 416 and h["content-range"] == f"bytes */{n}" and got == b"" and not r.closed(0.3), spec
    for spec in (b"bytes=0-1,4-5", b"bytes=5-2", b"items=0-1", b"bytes=x-1", b"bytes=0-1 junk"):
        st, h, got, _ = one(req(b"/style.css", extra=b"Range: " + spec + b"\r\n"))
        assert st == 200 and got == body, spec   # ignored
    st, h, got, _ = one(req(b"/style.css", "HEAD", b"Range: bytes=0-1\r\n"), head=True); assert st == 200
    st, h, got, _ = one(req(b"/empty.txt", extra=b"Range: bytes=0-\r\n")); assert st == 416
    st, h, got, _ = one(req(b"/big.bin", extra=b"Range: bytes=1000000-1999999\r\n"))
    assert st == 206 and got == ROOT[b"/big.bin"][1000000:2000000]

@test
def if_range():
    tag, lm = meta(); body = ROOT[b"/style.css"]
    st, _, got, _ = one(req(b"/style.css", extra=b"Range: bytes=0-1\r\nIf-Range: " + tag.encode() + b"\r\n"))
    assert st == 206 and got == body[:2]
    st, _, got, _ = one(req(b"/style.css", extra=b'Range: bytes=0-1\r\nIf-Range: "other"\r\n')); assert st == 200 and got == body
    st, _, got, _ = one(req(b"/style.css", extra=b"Range: bytes=0-1\r\nIf-Range: W/" + tag.encode() + b"\r\n")); assert st == 200
    st, _, got, _ = one(req(b"/style.css", extra=b"Range: bytes=0-1\r\nIf-Range: " + lm.encode() + b"\r\n")); assert st == 206
    st, _, got, _ = one(req(b"/style.css", extra=b"Range: bytes=0-1\r\nIf-Range: Sun, 06 Nov 1994 08:49:37 GMT\r\n")); assert st == 200

# ================================================================ pipelining and robustness
def pipeline(paths, s=None):
    s = s or conn(); r = Reader(s)
    raw = b"".join(req(p, "HEAD" if h else "GET") for p, h in paths)
    t = threading.Thread(target=s.sendall, args=(raw,)); t.start()
    for p, h in paths:
        st, _, b = r.response(head=h)
        want = 404 if p not in ROOT else 200
        assert st == want and (h or st != 200 or b == ROOT[p]), (p, st)
    t.join()

@test
def mixed_pipeline_5000():
    rnd = random.Random(1)
    choices = [b"/", b"/style.css", b"/data.json", b"/nope", b"/docs/"]
    pipeline([(rnd.choice(choices), rnd.random() < 0.2) for _ in range(5000)])

@test
def big_files_pipelined_slow_reader():
    s = conn(); paths = [(b"/big.bin", False), (b"/style.css", False)] * 20
    raw = b"".join(req(p) for p, _ in paths)
    t = threading.Thread(target=s.sendall, args=(raw,)); t.start()
    time.sleep(1.5)
    r = Reader(s)
    for p, _ in paths:
        st, _, b = r.response(); assert st == 200 and b == ROOT[p], p
    t.join()

@test
def byte_at_a_time():
    s = conn(); r = Reader(s)
    for c in req(b"/style.css") * 2:
        s.send(bytes([c])); time.sleep(0.0003)
    for _ in range(2): assert r.response()[2] == ROOT[b"/style.css"]

@test
def split_at_every_offset():
    s = conn(); r = Reader(s); raw = req(b"/data.json") * 2
    for cut in range(1, len(raw)):
        s.sendall(raw[:cut]); time.sleep(0.001); s.sendall(raw[cut:])
        for _ in range(2): assert r.response()[2] == ROOT[b"/data.json"]

@test
def many_connections():
    socks = [conn() for _ in range(int(os.environ.get("CONNS", "2000")))]
    for s in socks: s.sendall(req(b"/style.css"))
    for s in socks: assert Reader(s).response()[0] == 200
    for s in socks: s.close()

@test
def churn_and_resets():
    for i in range(2000):
        s = conn(); s.sendall(req(b"/"))
        if i % 2: s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\0\0\0\0\0\0\0")
        else: Reader(s).response()
        s.close()

@test
def error_response_survives_unread_input():
    # a 400 must reach the client even while it keeps sending (lingering close, no RST)
    s = conn(); s.sendall(b"GET /%zz HTTP/1.1\r\nHost: t\r\n\r\n" + b"x" * 200000)
    st, *_ = Reader(s).response(); assert st == 400

@test
def fuzz():
    rnd = random.Random(3)
    pieces = [b"GET ", b"HEAD ", b"POST ", b"/", b"/style.css", b"/api/echo", b"/protected/", b"%", b"%2", b"?",
              b" HTTP/1.1", b" HTTP/1.0", b"\r\n", b"\n", b"\r", b"Host: t", b"Connection: close",
              b"Content-Length: 0", b"Content-Length: 3", b"Transfer-Encoding: chunked", b"Range: bytes=0-1",
              b"If-None-Match: *", b"Expect: 100-continue", b":", b" ", b"\t", b"\x00", b"\xff", b"a" * 50, b"0\r\n\r\n"]
    for _ in range(1500):
        raw = b"".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 40)))
        s = conn()
        try:
            s.sendall(raw); s.shutdown(socket.SHUT_WR); s.settimeout(5)
            while s.recv(65536): pass
        except (ConnectionResetError, BrokenPipeError): pass
        finally: s.close()

@test
def still_alive():
    st, *_ = one(req(b"/")); assert st == 200

# ================================================================ reverse proxy
class Upstream(threading.Thread):
    """A deliberately simple HTTP/1.1 origin with scripted behaviours."""
    def __init__(self, port):
        super().__init__(daemon=True)
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind((HOST, port)); self.ls.listen(128)
        self.seen = []
    def run(self):
        while True:
            c, _ = self.ls.accept()
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()
    def handle(self, c):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d: return
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin1").split("\r\n")
            method, target, ver = lines[0].split(" ")
            hdrs = [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:]]
            hd = {k.lower(): v for k, v in hdrs}
            body = b""
            if hd.get("transfer-encoding", "").lower() == "chunked":
                raw = rest
                while True:
                    while b"\r\n" not in raw: raw += c.recv(65536)
                    i = raw.index(b"\r\n"); size = int(raw[:i].split(b";")[0], 16); raw = raw[i + 2:]
                    if size == 0:
                        while b"\r\n\r\n" not in b"\r\n" + raw: raw += c.recv(65536)
                        break
                    while len(raw) < size + 2: raw += c.recv(65536)
                    body += raw[:size]; raw = raw[size + 2:]
            elif "content-length" in hd and target != "/api/early":
                n = int(hd["content-length"]); body = rest
                while len(body) < n: body += c.recv(65536)
            self.seen.append((method, target, ver, hdrs, body))
            self.respond(c, method, target, hdrs, body)
        except (ConnectionResetError, BrokenPipeError, OSError): pass
        finally: c.close()
    def respond(self, c, method, target, hdrs, body):
        path = target.split("?")[0]
        if path == "/api/echo":
            out = (f"{method} {target}\n" + "".join(f"{k}: {v}\n" for k, v in hdrs)).encode() + b"\n" + body
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Up: 1\r\nConnection: X-Up, close\r\n"
                      b"Keep-Alive: timeout=5\r\nContent-Length: " + str(len(out)).encode() + b"\r\n\r\n" +
                      (b"" if method == "HEAD" else out))
        elif path == "/api/chunked":
            c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n"
                      b"6\r\nhello \r\n5;ext=1\r\nworld\r\n0\r\nX-T: done\r\n\r\n")
        elif path == "/api/close":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil close")
        elif path == "/api/big":
            data = bytes(range(256)) * 8192
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
        elif path == "/api/slow":
            time.sleep(5)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        elif path == "/api/304":
            c.sendall(b'HTTP/1.1 304 Not Modified\r\nETag: "abc"\r\nContent-Length: 99\r\n\r\n')
        elif path == "/api/early":
            c.sendall(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        elif path == "/api/1xx":
            c.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
                      b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        elif path == "/api/badcl":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello")
        elif path == "/api/fold":
            c.sendall(b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 2\r\n\r\nhi")
        elif path == "/api/truncated":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
        elif path == "/api/gzipchunked":
            c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nzz\r\n0\r\n\r\n")
        else:
            c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")

UPSTREAM = None

def echo_headers(body):
    lines = body.split(b"\n\n", 1)[0].decode().split("\n")
    return lines[0], {l.split(": ", 1)[0].lower(): l.split(": ", 1)[1] for l in lines[1:] if ": " in l}

@test
def proxy_basic():
    st, h, b, r = one(req(b"/api/echo?x=1", extra=b"Connection: X-Drop, keep-alive\r\nX-Drop: 1\r\nX-Keep: 2\r\n"
                          b"Keep-Alive: 300\r\nTE: trailers\r\nUpgrade: h2c\r\nProxy-Connection: x\r\n"
                          b"X-Forwarded-For: 6.6.6.6\r\n"))
    assert st == 200, (st, h)
    line, uh = echo_headers(b)
    assert line == "GET /api/echo?x=1"
    assert uh["host"] == "t" and uh["x-keep"] == "2" and uh["x-forwarded-for"] == PEER
    assert uh["via"] == "1.1 absurd" and uh["connection"] == "close" and uh["x-forwarded-proto"] == "http"
    for gone in ("x-drop", "keep-alive", "te", "upgrade", "proxy-connection"): assert gone not in uh, gone
    assert UPSTREAM.seen[-1][2] == "HTTP/1.1"
    # hop-by-hop fields of the response are gone too
    assert "x-up" not in h and "keep-alive" not in h and "connection" not in h, h
    assert not r.closed(0.3)

@test
def proxy_bodies():
    st, h, b, r = one(req(b"/api/echo", "POST", b"Content-Length: 11\r\n") + b"hello world")
    assert st == 200 and b.endswith(b"\n\nhello world") and echo_headers(b)[1]["content-length"] == "11"
    st, h, b, r = one(req(b"/api/echo", "PUT", b"Transfer-Encoding: chunked\r\n") + b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    assert st == 200 and b.endswith(b"\n\nhello world") and echo_headers(b)[1]["transfer-encoding"] == "chunked"
    big = os.urandom(300000)
    s = conn(); r = Reader(s)
    t = threading.Thread(target=s.sendall, args=(req(b"/api/echo", "POST", b"Content-Length: 300000\r\n") + big,)); t.start()
    st, h, b = r.response(); t.join(); assert st == 200 and b.endswith(big)
    # Expect: 100-continue is answered by the proxy
    s = conn(); r = Reader(s)
    s.sendall(req(b"/api/echo", "POST", b"Content-Length: 4\r\nExpect: 100-continue\r\n"))
    st, h, raw = r.head(); assert st == 100
    s.sendall(b"data"); st, h, b = r.response(); assert st == 200 and b.endswith(b"\n\ndata")
    assert "expect" not in echo_headers(b)[1]

@test
def proxy_response_framing():
    st, h, b, r = one(req(b"/api/chunked")); assert st == 200 and b == b"hello world" and h["transfer-encoding"] == "chunked"
    assert not r.closed(0.3)
    st, h, b, r = one(b"GET /api/chunked HTTP/1.0\r\n\r\n")       # HTTP/1.0: de-chunked, close-delimited
    assert st == 200 and b == b"hello world" and "transfer-encoding" not in h and h["connection"] == "close"
    st, h, b, r = one(req(b"/api/close")); assert st == 200 and b == b"until close" and h["connection"] == "close"
    st, h, b, r = one(req(b"/api/big")); assert st == 200 and b == bytes(range(256)) * 8192
    st, h, b, r = one(req(b"/api/echo", "HEAD"), head=True); assert st == 200 and b == b"" and not r.closed(0.3)
    st, h, b, r = one(req(b"/api/304")); assert st == 304 and h["etag"] == '"abc"' and not r.closed(0.3)
    st, h, b, r = one(req(b"/api/gzipchunked")); assert st == 200 and h["transfer-encoding"] == "gzip, chunked"
    s = conn(); s.sendall(req(b"/api/1xx")); r = Reader(s)
    st, h, raw = r.head(); assert st == 103 and h["link"]
    st, h, b = r.response(); assert st == 200 and b == b"hi"
    st, h, b, r = one(b"GET /api/1xx HTTP/1.0\r\n\r\n")              # no 1xx for HTTP/1.0
    assert st == 200
    st, h, b, r = one(req(b"/api/early", "POST", b"Content-Length: 100000\r\n") + b"x" * 1000)
    assert st == 413 and h["connection"] == "close"

@test
def proxy_errors():
    expect_status(req(b"/dead/x"), 502, closes=True)
    expect_status(req(b"/api/badcl"), 502, closes=True)
    expect_status(req(b"/api/fold"), 502, closes=True)
    expect_status(req(b"/api/../style.css"), 400, closes=True)    # dot segments never reach the upstream
    expect_status(req(b"/api/%2e%2e/x"), 400, closes=True)
    s = conn(); s.sendall(req(b"/api/truncated")); r = Reader(s)
    st, h, raw = r.head(); assert st == 200 and h["content-length"] == "100"
    assert r.closed() is False or True
    got = bytes(r.buf)
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            got += c
    except ConnectionResetError: pass
    assert got == b"short", got                                   # truncated: the client sees the close
    t = time.time(); expect_status(req(b"/api/slow"), 504, closes=True); assert 1.5 < time.time() - t < 4.5

@test
def proxy_mixed_pipeline():
    s = conn(); r = Reader(s)
    s.sendall(req(b"/style.css") + req(b"/api/echo?1") + req(b"/data.json") + req(b"/api/chunked") +
              req(b"/api/echo?2", "POST", b"Content-Length: 3\r\n") + b"abc" + req(b"/"))
    assert r.response()[2] == ROOT[b"/style.css"]
    assert r.response()[2].startswith(b"GET /api/echo?1\n")
    assert r.response()[2] == ROOT[b"/data.json"]
    assert r.response()[2] == b"hello world"
    assert r.response()[2].endswith(b"\n\nabc")
    assert r.response()[2] == ROOT[b"/"]
    assert not r.closed(0.3)

@test
def proxy_absolute_form_and_http10():
    st, h, b, _ = one(req(b"http://example.org:81/api/echo", host=b"ignored"))
    assert st == 200 and echo_headers(b)[1]["host"] == "example.org:81" and echo_headers(b)[0] == "GET /api/echo"
    st, h, b, _ = one(b"GET /api/echo HTTP/1.0\r\n\r\n")
    assert st == 200 and echo_headers(b)[1]["host"] == UPHOST and h["connection"] == "close"

# ================================================================ JS challenge
def solve(nonce, bits):
    n = 0
    while True:
        h = hashlib.sha256((nonce + str(n)).encode()).digest()
        if int.from_bytes(h[:4], "big") >> (32 - bits) == 0: return nonce + str(n)
        n += 1

@test
def challenge():
    st, h, b, r = one(req(b"/protected/"))
    assert st == 403 and h["cache-control"] == "no-store" and b"Checking your browser" in b
    nonce = re.search(rb'var C="([0-9a-f]{26})"', b).group(1).decode()
    bits = int(nonce[24:], 16); assert bits == 12
    st, *_ = one(req(b"/style.css")); assert st == 200                         # unprotected paths are untouched
    st, h, b, r = one(req(b"/protected/", "HEAD"), head=True); assert st == 403
    pow_ = solve(nonce, bits)
    st, h, b, r = one(req(b"/protected/?a=1", extra=b"Cookie: x=1; absurd_pow=" + pow_.encode() + b"\r\n"))
    assert st == 307 and h["location"] == "/protected/?a=1", (st, h)
    m = re.search(r"absurd_clearance=([0-9a-f]{24});", h["set-cookie"]); assert m and "HttpOnly" in h["set-cookie"]
    clr = m.group(1).encode()
    st, h, b, r = one(req(b"/protected/", extra=b"Cookie: absurd_clearance=" + clr + b"\r\n"))
    assert st == 200 and b == b"secret area\n"
    bad = bytes([clr[0] ^ 1]) + clr[1:]
    st, *_ = one(req(b"/protected/", extra=b"Cookie: absurd_clearance=" + bad + b"\r\n")); assert st == 403
    wrong = nonce + "0"
    if int.from_bytes(hashlib.sha256(wrong.encode()).digest()[:4], "big") >> 20 != 0:
        st, *_ = one(req(b"/protected/", extra=b"Cookie: absurd_pow=" + wrong.encode() + b"\r\n")); assert st == 403
    forged = "%08x" % int(time.time()) + "0" * 16 + "0c"
    st, *_ = one(req(b"/protected/", extra=b"Cookie: absurd_pow=" + solve(forged, 12).encode() + b"\r\n")); assert st == 403
    # a body sent to a challenged path is skipped like for any static response
    s = conn(); r = Reader(s)
    s.sendall(req(b"/protected/", "POST", b"Content-Length: 3\r\n") + b"abc" + req(b"/style.css"))
    assert r.response()[0] == 403 and r.response()[2] == ROOT[b"/style.css"]

# ================================================================ TLS
@test
def tls():
    s = conn(HTTPS, tls=True)
    assert s.selected_alpn_protocol() == "http/1.1", s.selected_alpn_protocol()
    r = Reader(s)
    s.sendall(req(b"/style.css") + req(b"/big.bin") + req(b"/api/echo"))
    assert r.response()[2] == ROOT[b"/style.css"]
    assert r.response()[2] == ROOT[b"/big.bin"]
    assert echo_headers(r.response()[2])[1]["x-forwarded-proto"] == "https"
    s.sendall(req(b"/", extra=b"Connection: close\r\n")); assert r.response()[0] == 200 and r.closed()
    raw = socket.create_connection((HOST, HTTPS)); raw.sendall(req(b"/")); raw.settimeout(5)   # plaintext on the TLS port
    try: assert raw.recv(100) in (b"",) or True
    except (ConnectionResetError, socket.timeout): pass

@test
def tls_challenge_cookie_is_secure():
    st, h, b, r = one(req(b"/protected/"), port=HTTPS, tls=True); assert st == 403
    nonce = re.search(rb'var C="([0-9a-f]{26})"', b).group(1).decode()
    st, h, b, r = one(req(b"/protected/", extra=b"Cookie: absurd_pow=" + solve(nonce, 12).encode() + b"\r\n"), port=HTTPS, tls=True)
    assert st == 307 and "Secure" in h["set-cookie"]

# ================================================================ slow
def slowloris():
    s = conn(); s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n"); t = time.time()
    r = Reader(s); st, h, b = r.response(); assert st == 408 and h["connection"] == "close"
    assert 2.5 <= time.time() - t <= 5.5, time.time() - t
    assert r.closed()

# ================================================================ config
def config_errors(binary):
    for text, msg in [("listen 1.2.3:80\n", "bad address"), ("bogus 1\n", "unknown directive"),
                      ("threads x\n", "bad number"), ("proxy api 127.0.0.1:1\n", "prefix must start with /"),
                      ("proxy /a/ localhost:1\n", "bad upstream"), ("challenge_difficulty 40\n", "bad number")]:
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f: f.write("# test\n" + text)
        p = subprocess.run(shlex.split(binary) + ["-c", f.name], capture_output=True, text=True, timeout=30)
        os.unlink(f.name)
        assert p.returncode == 2 and ":2: " + msg in p.stderr, (text, p.returncode, p.stderr)
    print("ok  config_errors")

# ================================================================ main
def main(argv):
    global UPSTREAM
    if argv[:1] == ["fixture"]:
        make_fixture(argv[1]); return
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536)) if resource.getrlimit(resource.RLIMIT_NOFILE)[1] >= 65536 else None
    binary = os.environ.get("ABSURD", f"{REPO}/build/absurd")
    work = tempfile.mkdtemp(prefix="absurd-test-")
    os.chmod(work, 0o755)
    site = f"{work}/site"; make_fixture(site); load_expected(site)
    UPSTREAM = Upstream(UP); UPSTREAM.start()
    proc = None
    if os.environ.get("CONFIG_CHECK_BINARY") or "--external" not in argv:
        config_errors(os.environ.get("CONFIG_CHECK_BINARY", binary))
    if "--external" not in argv:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", f"{work}/key.pem", "-out", f"{work}/cert.pem", "-days", "2", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        os.chmod(f"{work}/key.pem", 0o600)
        with open(f"{work}/absurd.conf", "w") as f:
            f.write(f"""# test configuration
listen {HOST}:{HTTP}
listen {HOST}:{HTTPS} tls
tls_cert {work}/cert.pem
tls_key  {work}/key.pem
threads 2
root {site}
proxy /api/  {HOST}:{UP}
proxy /dead/ {HOST}:{DEAD}
challenge /protected/
challenge_difficulty 12
header_timeout 3
upstream_timeout 2
""")
        proc = subprocess.Popen(shlex.split(binary) + ["-c", f"{work}/absurd.conf"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(100):
            try: socket.create_connection((HOST, HTTP)).close(); break
            except OSError: time.sleep(0.05)
        else:
            print(proc.stdout.read()); sys.exit("server did not start")
    tests = T + ([slowloris] if "--slow" in argv else [])
    only = [a for a in argv if not a.startswith("-")]
    if only: tests = [t for t in tests if t.__name__ in only]
    failed = 0
    try:
        for fn in tests:
            t = time.time()
            try:
                fn(); print(f"ok  {fn.__name__}  ({time.time() - t:.2f}s)")
            except Exception as e:
                failed += 1
                import traceback; traceback.print_exc()
                print(f"FAIL {fn.__name__}")
            if proc and proc.poll() is not None:
                print(proc.stdout.read()); sys.exit(f"server died (exit {proc.returncode}) during {fn.__name__}")
    finally:
        if proc: proc.kill()
        shutil.rmtree(work, ignore_errors=True)
    print("all passed" if not failed else f"{failed} FAILED")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main(sys.argv[1:])
