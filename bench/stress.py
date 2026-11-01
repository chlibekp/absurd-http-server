"""Correctness stress for absurd. Usage: python3 stress.py [port]"""
import re, socket, sys, time, threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
REQ = b"GET /plaintext HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n"
RESP = re.compile(
    rb"HTTP/1\.1 200 OK\r\nServer: absurd\r\nContent-Type: text/plain\r\n"
    rb"Content-Length: 13\r\nDate: (Sun|Mon|Tue|Wed|Thu|Fri|Sat), \d\d "
    rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d GMT"
    rb"\r\n\r\nHello, World!")
RLEN = 131

def conn():
    s = socket.create_connection(("127.0.0.1", PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s

def read_n(s, n, timeout=10):
    s.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n * RLEN:
        chunk = s.recv(1 << 20)
        if not chunk:
            raise AssertionError(f"EOF after {len(buf)} bytes, wanted {n * RLEN}")
        buf += chunk
    assert len(buf) == n * RLEN, f"got {len(buf)} bytes, wanted {n * RLEN}"
    for i in range(n):
        assert RESP.fullmatch(buf[i * RLEN:(i + 1) * RLEN]), f"bad response #{i}: {bytes(buf[i*RLEN:(i+1)*RLEN])!r}"

def check(name, fn):
    t = time.time(); fn(); print(f"ok  {name}  ({time.time() - t:.2f}s)")

def single():
    s = conn(); s.sendall(REQ); read_n(s, 1)

def keepalive_many():
    s = conn()
    for _ in range(2000):
        s.sendall(REQ); read_n(s, 1)

def pipeline(n):
    def f():
        s = conn(); s.sendall(REQ * n); read_n(s, n)
    return f

def slow_reader():
    # 200k pipelined requests while not reading: forces short/async sends and the pending queue
    s = conn(); n = 200_000
    t = threading.Thread(target=s.sendall, args=(REQ * n,)); t.start()
    time.sleep(1.0)
    read_n(s, n, timeout=30); t.join()

def byte_at_a_time():
    s = conn()
    for b in REQ * 3:
        s.send(bytes([b])); time.sleep(0.0005)
    read_n(s, 3)

def split_everywhere():
    s = conn(); data = REQ * 4
    for cut in range(1, len(REQ)):
        s.sendall(data[:cut]); time.sleep(0.002); s.sendall(data[cut:])
        read_n(s, 4)

def many_connections():
    socks = [conn() for _ in range(3000)]
    for s in socks: s.sendall(REQ)
    for s in socks: read_n(s, 1)
    for s in socks: s.close()

def churn():
    for _ in range(3000):
        s = conn(); s.sendall(REQ); read_n(s, 1); s.close()

def reset_mid_pipeline():
    for _ in range(200):
        s = conn(); s.sendall(REQ * 500)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\0\0\0\0\0\0\0"); s.close()
    single()  # still alive

def garbage_then_valid():
    s = conn(); s.sendall(b"\x00\xff" * 5000 + b"\r\n\r\n"); read_n(s, 1)

for name, fn in [
    ("single request", single),
    ("2000 sequential keep-alive", keepalive_many),
    ("pipeline x1000 in one write", pipeline(1000)),
    ("pipeline x20000 in one write", pipeline(20000)),
    ("slow reader, 200k pipelined", slow_reader),
    ("byte-at-a-time", byte_at_a_time),
    ("request split at every offset", split_everywhere),
    ("3000 concurrent connections", many_connections),
    ("3000 connect/close churn", churn),
    ("RST mid-pipeline x200", reset_mid_pipeline),
    ("garbage then terminator", garbage_then_valid),
]:
    check(name, fn)
print("all passed")
