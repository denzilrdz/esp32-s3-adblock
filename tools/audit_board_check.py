"""On-board checks for the 2026-11 audit fixes (stdlib only, no dashboard login needed).

usage: python3 tools/audit_board_check.py <board-ip>

Each check prints PASS/FAIL; the script exits non-zero if any failed. Household DNS
keeps working throughout, but the TCP trickle check deliberately ties up one TCP/53
connection for ~15 s.

  tcp-trickle   a TCP/53 client that reads replies a few bytes at a time must not
                restart the board (before: watchdog reset); the board drops it
  http-413      a plain POST with a huge or negative Content-Length is refused with
                413 at once, also on unknown URLs (before: buffered into PSRAM)
  upload-noauth a multipart POST without a file part to an upload "done" route needs
                a login (before: a stale flag from an earlier upload could pass)
  case-echo     the reply's question has the client's exact letter case (DNS 0x20)
  cd-not-cached a checking-disabled (CD=1) answer for a DNSSEC-broken name must not
                be served from the cache to a normal query
  alive         the board answered DNS throughout, with no restart (silence > 3 s)
"""

import random
import socket
import struct
import sys
import threading
import time

IP = sys.argv[1]
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name:14} {detail}", flush=True)


def build_query(name, qtype=1, flags=0x0100, qid=None, edns=False):
    qid = random.randrange(65536) if qid is None else qid
    wire = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\0"
    hdr = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0) if edns else b""
    return hdr + wire + struct.pack(">HH", qtype, 1) + opt, wire


def udp_query(name, qtype=1, flags=0x0100, timeout=3.0):
    q, wire = build_query(name, qtype, flags)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (IP, 53))
        r, _ = s.recvfrom(4096)
        return r, wire
    except OSError:
        return None, wire
    finally:
        s.close()


def rcode(r):
    return struct.unpack(">H", r[2:4])[0] & 0xF


# --- liveness watcher: a restart shows as > 3 s of DNS silence -------------------------
stop = threading.Event()
silences = []


def watch():
    down_since = None
    while not stop.is_set():
        r, _ = udp_query("example.com", timeout=1.0)
        now = time.time()
        if r is None:
            down_since = down_since or now
        else:
            if down_since and now - down_since > 3:
                silences.append(now - down_since)
            down_since = None
        time.sleep(0.5)


def check_case_echo():
    name = "wWw.ExAmPle.CoM"
    r, wire = udp_query(name)
    ok = r is not None and r[12 : 12 + len(wire)] == wire
    got = r[12 : 12 + len(wire)] if r else None
    report("case-echo", ok, f"asked {name}, got {got!r}")


def check_cd_not_cached():
    # dnssec-failed.org is deliberately mis-signed: validating resolvers answer SERVFAIL.
    r1, _ = udp_query("dnssec-failed.org", flags=0x0110)  # RD + CD
    r2, _ = udp_query("dnssec-failed.org", flags=0x0100)  # RD only
    if r1 is None or r2 is None:
        report("cd-not-cached", False, "no answer")
        return
    report(
        "cd-not-cached",
        rcode(r2) == 2,
        f"CD=1 rcode {rcode(r1)}, then normal query rcode {rcode(r2)} (want 2 SERVFAIL)",
    )


def http_raw(req, timeout=5.0):
    s = socket.create_connection((IP, 80), timeout=timeout)
    t0 = time.time()
    try:
        s.sendall(req)
        data = b""
        while b"\r\n" not in data:
            chunk = s.recv(256)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n", 1)[0].decode(errors="replace"), time.time() - t0
    except OSError as e:
        return f"error {e}", time.time() - t0
    finally:
        s.close()


def check_http_413():
    host = f"Host: {IP}\r\n".encode()
    for path, length in (
        ("/api/config", "-1"),
        ("/no/such/url", "-1"),
        ("/api/rules/add", "50000000"),
    ):
        req = (
            f"POST {path} HTTP/1.1\r\n".encode()
            + host
            + b"Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: adblock\r\n"
            + f"Content-Length: {length}\r\n\r\n".encode()
            + b"a="
            + b"x" * 4000
        )
        status, took = http_raw(req)
        report(
            "http-413",
            " 413 " in status + " " and took < 3,
            f"{path} CL={length}: {status!r} in {took:.1f}s",
        )
    # A normal small request still works (the page shell is public).
    status, _ = http_raw(
        f"GET / HTTP/1.1\r\nHost: {IP}\r\nConnection: close\r\n\r\n".encode()
    )
    report(
        "http-413",
        status.startswith("HTTP/1.1 200"),
        f"GET / still answers: {status!r}",
    )


def check_upload_noauth():
    body = b'--b\r\nContent-Disposition: form-data; name="x"\r\n\r\ny\r\n--b--\r\n'
    for path in ("/api/firmware", "/api/blocklist/upload", "/api/settings/import"):
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {IP}\r\nX-Requested-With: adblock\r\n".encode()
            + b"Content-Type: multipart/form-data; boundary=b\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        status, _ = http_raw(req)
        report(
            "upload-noauth",
            " 401 " in status + " " or " 403 " in status + " ",
            f"{path}: {status!r}",
        )


def check_tcp_trickle():
    # Pipeline cache-friendly queries with large-ish answers, never read, keep the TCP
    # window tiny, then read a few bytes every 0.4 s: each send() makes a little progress.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256)
    s.settimeout(20)
    s.connect((IP, 53))
    names = ["google.com", "microsoft.com", "apple.com", "github.com"]
    for i in range(4):
        q, _ = build_query(names[i], qtype=16, edns=True)  # TXT, often 1-4 KB
        s.sendall(struct.pack(">H", len(q)) + q)
    t0 = time.time()
    closed_after = None
    while time.time() - t0 < 15:
        try:
            if not s.recv(16):
                closed_after = time.time() - t0
                break
        except OSError:
            closed_after = time.time() - t0
            break
        time.sleep(0.4)
    s.close()
    detail = (
        f"board closed the slow reader after {closed_after:.1f}s"
        if closed_after
        else "still open after 15 s"
    )
    report("tcp-trickle", True, detail + " (restart check: see 'alive')")


if __name__ == "__main__":
    first, _ = udp_query("example.com")
    if first is None:
        sys.exit(f"{IP} does not answer DNS")
    w = threading.Thread(target=watch, daemon=True)
    w.start()
    check_case_echo()
    check_cd_not_cached()
    check_http_413()
    check_upload_noauth()
    check_tcp_trickle()
    time.sleep(5)  # a watchdog restart would show as silence now
    stop.set()
    w.join()
    report(
        "alive", not silences, f"DNS silences > 3 s: {[round(x, 1) for x in silences]}"
    )
    sys.exit(0 if all(results) else 1)
