"""DNS load test against the ad blocker (stdlib only).

usage: python3 tools/dns_load.py <board-ip> <total-queries> <max-qps> [workers]

2026-10-23, v0.2.6: 60000 queries at 71 q/s, no restart, 0.9% SERVFAIL, 0.1% timeout.

Mix: unique names (forces an upstream round trip), popular names (cache hits),
A/AAAA/HTTPS/TXT, ~3% over TCP, a few blocked names, and bursts. Prints progress every
10 s and flags when the board stops answering (a restart takes ~10-20 s).
"""

import random
import socket
import struct
import sys
import threading
import time

IP, TOTAL, QPS = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
WORKERS = int(sys.argv[4]) if len(sys.argv) > 4 else 24

POPULAR = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.net",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "netflix.com",
    "amazon.com",
    "github.com",
    "cloudflare.com",
    "wikipedia.org",
    "reddit.com",
    "spotify.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "yahoo.com",
    "bing.com",
    "office.com",
    "live.com",
    "zoom.us",
    "slack.com",
    "discord.com",
]
BLOCKED = [
    "doubleclick.net",
    "googleadservices.com",
    "ads.yahoo.com",
    "adservice.google.com",
]
TYPES = [1, 1, 1, 28, 28, 65, 16]  # A A A AAAA AAAA HTTPS TXT

lock = threading.Lock()
stats = {"sent": 0, "ok": 0, "nx": 0, "servfail": 0, "other": 0, "timeout": 0, "tcp": 0}
last_ok = [time.time()]
outages = []
next_slot = [time.time()]
counter = [0]


def build(name, qtype, qid):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q + b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)  # EDNS0


def pick(rng):
    r = rng.random()
    if r < 0.45:
        name = "%s%d.%s" % (
            rng.choice("abcdefgh"),
            rng.getrandbits(40),
            rng.choice(POPULAR),
        )
    elif r < 0.95:
        name = rng.choice(POPULAR)
        if rng.random() < 0.5:
            name = "www." + name
    else:
        name = rng.choice(BLOCKED)
    return name, rng.choice(TYPES)


def ask(rng, name, qtype, tcp):
    qid = rng.getrandbits(16)
    pkt = build(name, qtype, qid)
    if tcp:
        with socket.create_connection((IP, 53), timeout=3) as s:
            s.sendall(struct.pack(">H", len(pkt)) + pkt)
            hdr = s.recv(2)
            if len(hdr) < 2:
                return None
            n = struct.unpack(">H", hdr)[0]
            data = b""
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(pkt, (IP, 53))
            data, _ = s.recvfrom(4096)
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
        return None
    return data[3] & 0x0F


def worker(seed):
    rng = random.Random(seed)
    while True:
        with lock:
            if counter[0] >= TOTAL:
                return
            counter[0] += 1
            # Rate limit with occasional bursts (100 queries back to back).
            burst = counter[0] % 2000 < 100
            now = time.time()
            wait = 0 if burst else max(0.0, next_slot[0] - now)
            next_slot[0] = max(next_slot[0], now) + (0 if burst else 1.0 / QPS)
        if wait:
            time.sleep(wait)
        name, qtype = pick(rng)
        tcp = rng.random() < 0.03
        try:
            rc = ask(rng, name, qtype, tcp)
        except (socket.timeout, OSError):
            rc = None
        with lock:
            stats["sent"] += 1
            stats["tcp"] += tcp
            if rc is None:
                stats["timeout"] += 1
            else:
                stats[{0: "ok", 3: "nx", 2: "servfail"}.get(rc, "other")] += 1
                gap = time.time() - last_ok[0]
                if gap > 8:
                    outages.append((time.strftime("%H:%M:%S"), round(gap, 1)))
                    print(
                        "!! board was silent for %.1f s (restart?) until %s"
                        % (gap, time.strftime("%H:%M:%S")),
                        flush=True,
                    )
                last_ok[0] = time.time()


def main():
    start = time.time()
    threads = [
        threading.Thread(target=worker, args=(i,), daemon=True) for i in range(WORKERS)
    ]
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        time.sleep(10)
        with lock:
            el = time.time() - start
            silent = time.time() - last_ok[0]
            print(
                "%s  %6d sent  %.0f q/s  ok %d nx %d servfail %d timeout %d tcp %d%s"
                % (
                    time.strftime("%H:%M:%S"),
                    stats["sent"],
                    stats["sent"] / el,
                    stats["ok"],
                    stats["nx"],
                    stats["servfail"],
                    stats["timeout"],
                    stats["tcp"],
                    "   (silent %.0f s)" % silent if silent > 5 else "",
                ),
                flush=True,
            )
    print(
        "done in %.0f s: %s outages=%s" % (time.time() - start, stats, outages),
        flush=True,
    )


main()
