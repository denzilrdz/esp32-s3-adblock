"""On-board watchdog self-test: every kind of hang must end in a restart with its reason.

usage: python3 tools/selftest_board.py <host> <netrc-file> [hang ...]

Needs the self-test firmware (pio run -e esp32s3_selftest) and the dashboard login
in a netrc file ("machine <host> login admin password ..."; curl reads it, nothing is
printed). The script flashes .pio/build/esp32s3_selftest/firmware.bin, waits until
the new image is marked valid (60 s healthy, else it would roll back), then for each
hang triggers POST /api/selftest?hang=<what>, waits for the restart and checks the
"Last restart" line from /api/stats. At the end it flashes the release build
(.pio/build/esp32s3/firmware.bin) back. Household DNS is down for ~10 s per hang.
"""

import json
import pathlib
import socket
import struct
import subprocess
import sys
import time

HOST, NETRC = sys.argv[1], sys.argv[2]
ROOT = pathlib.Path(__file__).resolve().parent.parent
SELFTEST_BIN = ROOT / ".pio/build/esp32s3_selftest/firmware.bin"
RELEASE_BIN = ROOT / ".pio/build/esp32s3/firmware.bin"

# hang -> text the "Last restart" summary must contain
EXPECT = {
    "web": "web task stuck",
    "download": "blocklist download stuck",
    "upstream": "upstream task stuck",
    "checker": "software watchdog stopped",
    "upstream-hw": "crash",
    "idle0": "crash",
}
HANGS = sys.argv[3:] or list(EXPECT)


def curl(*args, timeout=60):
    cmd = [
        "curl",
        "-s",
        "-m",
        str(timeout),
        "--netrc-file",
        NETRC,
        "-H",
        "X-Requested-With: adblock",
    ]
    r = subprocess.run(cmd + list(args), capture_output=True, text=True)
    return r.stdout


def stats():
    try:
        return json.loads(curl("http://%s/api/stats" % HOST, timeout=5))
    except (ValueError, OSError):
        return None


def dns_alive():
    q = (
        struct.pack(">HHHHHH", 0x4243, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        try:
            s.sendto(q, (socket.gethostbyname(HOST), 53))
            s.recvfrom(512)
            return True
        except OSError:
            return False


def wait_restart(limit_s):
    """Waits for DNS to go silent and come back; returns seconds until it went silent."""
    start = time.time()
    while time.time() - start < limit_s:
        if not dns_alive():
            down = time.time() - start
            while not dns_alive():
                if time.time() - start > limit_s + 60:
                    return None
                time.sleep(0.5)
            return down
        time.sleep(0.5)
    return None


def wait_up(extra_s=0):
    while True:
        s = stats()
        if s:
            if extra_s:
                time.sleep(extra_s)
            return stats()
        time.sleep(2)


def flash(path):
    print("flashing %s ..." % path.relative_to(ROOT), flush=True)
    print(
        "  ",
        curl(
            "-F", "f=@%s" % path, "http://%s/api/firmware" % HOST, timeout=180
        ).strip(),
        flush=True,
    )
    wait_restart(60)


def main():
    for p in (SELFTEST_BIN, RELEASE_BIN):
        if not p.exists():
            sys.exit("build first: %s missing" % p)
    if not stats():
        sys.exit("can't read /api/stats: check the host and the netrc login")
    flash(SELFTEST_BIN)
    s = wait_up(extra_s=75)  # until the new image is marked valid
    print(
        "running self-test firmware v%s, last restart: %s"
        % (s["version"], s["restart"]["summary"])
    )

    results = []
    for hang in HANGS:
        print("\n== hang %s (expect '%s')" % (hang, EXPECT[hang]), flush=True)
        t0 = time.time()
        print(
            "  ",
            curl(
                "-X", "POST", "http://%s/api/selftest?hang=%s" % (HOST, hang), timeout=5
            ).strip(),
        )
        down = wait_restart(120)
        s = wait_up(extra_s=3)
        r = s["restart"]
        ok = down is not None and EXPECT[hang] in r["summary"]
        crash = r.get("crash")
        print(
            "   restarted after %s s; last restart: %s"
            % (round(down, 1) if down else "-", r["summary"])
        )
        if crash:
            print(
                "   crash record (%s): task %s, %s"
                % (
                    "this restart" if crash["thisBoot"] else "earlier",
                    crash["task"],
                    crash["reason"],
                )
            )
        print(
            "   %s (%.0f s)" % ("PASS" if ok else "FAIL", time.time() - t0), flush=True
        )
        results.append((hang, ok, r["summary"]))

    flash(RELEASE_BIN)
    s = wait_up(extra_s=5)
    print(
        "\nback on release firmware v%s, last restart: %s"
        % (s["version"], s["restart"]["summary"])
    )
    print("\nsummary:")
    for hang, ok, summary in results:
        print("  %-12s %s  %s" % (hang, "PASS" if ok else "FAIL", summary))
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


main()
