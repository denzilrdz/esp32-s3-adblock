"""Slow HTTP client against the dashboard: checks that one slow device can't reset the board.

usage: python3 tools/http_stall.py <board-ip> [hold-seconds] [stall|trickle]

stall:   full request, then never read the 46 KB answer (blocked send)
trickle: request headers one short line per second, never finished (slow parse)

A phone that sleeps or roams mid-request looks like this. Up to v0.2.7 the web task
busy-waited at priority 3 and starved IDLE0, so the 5 s task watchdog reset the board
(trickle mode reproduced it in 6 s). The script watches DNS: a reset shows as a few
seconds of silence. Expected from v0.2.8 on: "no restart".
"""

import socket
import struct
import sys
import time

IP = sys.argv[1]
HOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 25
MODE = sys.argv[3] if len(sys.argv) > 3 else "stall"


def dns_alive():
    q = (
        struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        try:
            s.sendto(q, (IP, 53))
            s.recvfrom(512)
            return True
        except OSError:
            return False


print("DNS alive before:", dns_alive(), flush=True)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)  # tiny window, then never read
s.connect((IP, 80))
if MODE == "stall":
    s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % IP).encode())
else:
    s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\n" % IP).encode())
start = time.time()
last_line = start
down_at = None
while time.time() - start < HOLD:
    alive = dns_alive()
    t = time.time() - start
    if not alive and down_at is None:
        down_at = t
        print("%5.1f s: DNS stopped answering" % t, flush=True)
    elif alive and down_at is not None and down_at >= 0:
        print(
            "%5.1f s: DNS back (silent %.1f s: the board restarted)" % (t, t - down_at),
            flush=True,
        )
        down_at = -1
    if MODE == "trickle" and time.time() - last_line >= 1 and time.time() - start < 12:
        try:
            s.sendall(b"X-Slow: 1\r\n")
        except OSError:
            pass
        last_line = time.time()
    time.sleep(0.5)
s.close()
print(
    "result:",
    "board restarted" if down_at == -1 else ("still down" if down_at else "no restart"),
    flush=True,
)
