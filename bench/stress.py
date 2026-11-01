"""Correctness and hostile-input tests for absurd.

    python3 stress.py fixture DIR      # write the test site into DIR
    python3 stress.py run [PORT]       # run against a server serving that DIR
    python3 stress.py run PORT --slow  # also run the 15 s header-timeout test
"""
import os, random, re, socket, sys, threading, time

def make_fixture(d):
    os.makedirs(f"{d}/docs/deep", exist_ok=True)
    os.makedirs(f"{d}/.git", exist_ok=True)
    os.makedirs(f"{d}/with space", exist_ok=True)
    w = lambda p, b: open(f"{d}/{p}", "wb").write(b)
    w("index.html", b"<!doctype html><title>t</title>hello\n")
    w("style.css", b"body{color:red}\n")
    w("data.json", b'{"ok":true}\n')
    w("docs/index.html", b"docs\n")
    w("docs/deep/page.txt", b"deep\n")
    w("with space/a b.txt", b"spaced\n")
    w(".env", b"SECRET=1\n")
    w(".git/config", b"[core]\n")
    w("empty.txt", b"")
    random.seed(7)
    w("big.bin", bytes(random.getrandbits(8) for _ in range(3_000_000)))
    for name, target in (("passwd", "/etc/passwd"), ("docslink", "docs"), ("up", "..")):
        try: os.symlink(target, f"{d}/{name}")
        except FileExistsError: pass

PORT = 8080
ROOT = None  # expected file contents, filled in run()

def conn():
    s = socket.create_connection(("127.0.0.1", PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(20)
    return s

class Reader:
    def __init__(self, s): self.s, self.buf = s, bytearray()
    def fill(self):
        c = self.s.recv(1 << 20)
        if not c: raise EOFError
        self.buf += c
    def response(self, head=False):
        while b"\r\n\r\n" not in self.buf: self.fill()
        i = self.buf.index(b"\r\n\r\n")
        lines = self.buf[:i].decode("latin1").split("\r\n")
        del self.buf[:i + 4]
        status = int(lines[0].split()[1])
        h = {}
        for l in lines[1:]:
            k, v = l.split(":", 1); h[k.strip().lower()] = v.strip()
        n = 0 if head or status == 304 else int(h.get("content-length", 0))
        while len(self.buf) < n: self.fill()
        body = bytes(self.buf[:n]); del self.buf[:n]
        return status, h, body
    def closed(self, timeout=3):
        self.s.settimeout(timeout)
        try: return self.s.recv(1) == b"" and not self.buf
        except (ConnectionResetError, BrokenPipeError): return True
        except socket.timeout: return False

def req(path, method="GET", extra=b"", ver=b"HTTP/1.1"):
    return method.encode() + b" " + path + b" " + ver + b"\r\nHost: t\r\n" + extra + b"\r\n"

def one(raw, head=False):
    s = conn(); s.sendall(raw); r = Reader(s)
    st, h, b = r.response(head)
    return st, h, b, r

def expect_status(raw, code, closes=None):
    st, h, b, r = one(raw)
    assert st == code, f"{raw[:60]!r}: got {st}, want {code}"
    if closes is not None:
        assert r.closed() == closes, f"{raw[:60]!r}: closed should be {closes}"
    return h, b

T = []
def test(fn): T.append(fn); return fn

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
        assert b == ROOT[path], path

@test
def query_and_fragment_ignored():
    st, _, b, _ = one(req(b"/style.css?v=3#x")); assert st == 200 and b == ROOT[b"/style.css"]

@test
def directory_redirect():
    h, _ = expect_status(req(b"/docs"), 301)
    assert h["location"] == "/docs/"
    h, _ = expect_status(req(b"/with%20space"), 301)
    assert h["location"] == "/with%20space/"

@test
def nothing_outside_the_snapshot():
    for p in [b"/.env", b"/.git/config", b"/passwd", b"/docslink/", b"/up/", b"/../../etc/passwd",
              b"/..%2f..%2fetc%2fpasswd", b"/%2e%2e/%2e%2e/etc/passwd", b"/docs/../.env",
              b"/docs/..%2f.env", b"/./index.html", b"//index.html", b"/index.html/", b"/proc/self/environ",
              b"/docs/deep", b"/docs/deep/"]:
        expect_status(req(p), 404 if p != b"/docs/deep" else 301)

@test
def etag_revalidation():
    st, h, _, _ = one(req(b"/style.css"))
    tag = h["etag"].encode()
    for inm in (tag, b"W/" + tag, b'"nope", ' + tag, b"*"):
        st, h2, b, _ = one(req(b"/style.css", extra=b"If-None-Match: " + inm + b"\r\n"))
        assert st == 304 and b == b"" and h2["etag"] == h["etag"], inm
    expect_status(req(b"/style.css", extra=b'If-None-Match: "0000000000000000"\r\n'), 200)

@test
def head_has_no_body():
    s = conn(); s.sendall(req(b"/big.bin", "HEAD") + req(b"/style.css")); r = Reader(s)
    st, h, b = r.response(head=True)
    assert st == 200 and h["content-length"] == "3000000" and b == b""
    st, h, b = r.response(); assert b == ROOT[b"/style.css"]

@test
def methods_and_versions():
    expect_status(req(b"/", "POST", b"Content-Length: 0\r\n"), 405, closes=True)
    expect_status(req(b"/", "get"), 405, closes=True)
    expect_status(req(b"/", "DELETE"), 405, closes=True)
    expect_status(req(b"/", ver=b"HTTP/2.0"), 505, closes=True)
    expect_status(req(b"/", ver=b"HTTP/1.x"), 505, closes=True)
    expect_status(req(b"/", ver=b"HTCPCP/1"), 400, closes=True)

@test
def http10_and_connection_header():
    st, h, _, r = one(b"GET / HTTP/1.0\r\n\r\n")
    assert st == 200 and h["connection"] == "close" and r.closed()
    s = conn(); s.sendall(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n" * 2); r = Reader(s)
    for _ in range(2):
        st, h, _ = r.response(); assert st == 200 and h["connection"] == "keep-alive"
    st, h, _, r = one(req(b"/", extra=b"Connection: close\r\n"))
    assert h["connection"] == "close" and r.closed()
    _, _, _, r = one(req(b"/"))
    assert not r.closed(timeout=0.5)

@test
def smuggling_and_bodies_rejected():
    expect_status(req(b"/", extra=b"Content-Length: 5\r\n") + b"hello", 413, closes=True)
    expect_status(req(b"/", extra=b"Transfer-Encoding: chunked\r\n") + b"0\r\n\r\n", 501, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n"), 501, closes=True)
    expect_status(req(b"/", extra=b"content-length: 1\r\n") + b"x", 413, closes=True)
    expect_status(req(b"/", extra=b"Content-Length: +0\r\n"), 413, closes=True)
    expect_status(req(b"/", extra=b"Content-Length:\r\n"), 400, closes=True)
    st, *_ = one(req(b"/", extra=b"Content-Length: 0\r\n")); assert st == 200

@test
def malformed_requests():
    bad = [b"GET / HTTP/1.1\nHost: t\n\n",                 # bare LF
           b"GET / HTTP/1.1\r\nHost: t\rX: y\r\n\r\n",     # bare CR
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\x00b\r\n\r\n",
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\x7fb\r\n\r\n",
           b"GET / HTTP/1.1\r\nHost: t\r\nX: a\r\n b\r\n\r\n",   # obs-fold
           b"GET / HTTP/1.1\r\nHost : t\r\n\r\n",          # space before colon
           b"GET / HTTP/1.1\r\nNoColon\r\n\r\n",
           b"GET / HTTP/1.1\r\n: empty\r\n\r\n",
           b"GET / HTTP/1.1\r\n\r\n",                      # 1.1 without Host
           b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
           b"GET http://t/ HTTP/1.1\r\nHost: t\r\n\r\n",   # absolute-form
           b"GET * HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /a b HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%zz HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%4 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /%00 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET /\xc3\xa9 HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET  / HTTP/1.1\r\nHost: t\r\n\r\n",
           b"GET / HTTP/1.1 \r\nHost: t\r\n\r\n",
           b"\x00\xff" * 100 + b"\r\n\r\n"]
    for raw in bad:
        expect_status(raw, 400, closes=True)

@test
def size_limits():
    expect_status(req(b"/" + b"a" * 3000), 414, closes=True)
    s = conn(); s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n" + b"X-Pad: " + b"a" * 20000 + b"\r\n\r\n")
    st, *_ = Reader(s).response(); assert st == 431
    st, *_ = one(req(b"/", extra=b"X-Big: " + b"a" * 12000 + b"\r\n")); assert st == 200

@test
def leading_crlf_tolerated():
    st, *_ = one(b"\r\n\r\n" + req(b"/")); assert st == 200

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
    random.seed(1)
    choices = [b"/", b"/style.css", b"/data.json", b"/nope", b"/docs/"]
    pipeline([(random.choice(choices), random.random() < 0.2) for _ in range(5000)])

@test
def big_files_pipelined_slow_reader():
    s = conn(); paths = [(b"/big.bin", False), (b"/style.css", False)] * 20
    raw = b"".join(req(p) for p, _ in paths)
    t = threading.Thread(target=s.sendall, args=(raw,)); t.start()
    time.sleep(1.5)                                  # let every buffer fill up
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
    socks = [conn() for _ in range(3000)]
    for s in socks: s.sendall(req(b"/style.css"))
    for s in socks: assert Reader(s).response()[0] == 200
    for s in socks: s.close()

@test
def churn_and_resets():
    for i in range(3000):
        s = conn(); s.sendall(req(b"/"))
        if i % 2:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\0\0\0\0\0\0\0")
        else:
            Reader(s).response()
        s.close()

@test
def fuzz():
    random.seed(3)
    pieces = [b"GET ", b"HEAD ", b"/", b"/style.css", b"%", b"%2", b"?", b" HTTP/1.1", b" HTTP/1.0",
              b"\r\n", b"\n", b"\r", b"Host: t", b"Connection: close", b"Content-Length: 0",
              b"If-None-Match: *", b":", b" ", b"\t", b"\x00", b"\xff", b"a" * 50]
    for _ in range(1500):
        raw = b"".join(random.choice(pieces) for _ in range(random.randint(1, 40)))
        s = conn()
        try:
            s.sendall(raw); s.shutdown(socket.SHUT_WR); s.settimeout(3)
            while s.recv(65536): pass
        except (ConnectionResetError, BrokenPipeError): pass
        finally: s.close()

@test
def still_alive():
    st, *_ = one(req(b"/")); assert st == 200

def slowloris():
    s = conn(); s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n"); t = time.time()
    s.settimeout(25)
    assert s.recv(1) == b"", "server should drop an unfinished request"
    assert 14 <= time.time() - t <= 18, time.time() - t

def run(argv):
    global PORT, ROOT
    if argv: PORT = int(argv[0])
    fx = os.environ.get("FIXTURE", "/tmp/site")
    ROOT = {}
    for p in ["index.html", "style.css", "data.json", "docs/index.html", "docs/deep/page.txt",
              "with space/a b.txt", "big.bin", "empty.txt"]:
        ROOT[b"/" + p.replace(" ", "%20").encode()] = open(f"{fx}/{p}", "rb").read()
    ROOT[b"/"] = ROOT[b"/index.html"]; ROOT[b"/docs/"] = ROOT[b"/docs/index.html"]
    tests = T + ([slowloris] if "--slow" in argv else [])
    for fn in tests:
        t = time.time(); fn(); print(f"ok  {fn.__name__}  ({time.time() - t:.2f}s)")
    print("all passed")

if __name__ == "__main__":
    if sys.argv[1] == "fixture": make_fixture(sys.argv[2])
    else: run(sys.argv[2:])
