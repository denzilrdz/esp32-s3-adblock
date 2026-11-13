#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a hashed blocklist for the ad blocker.

Output is format v2 (see docs/ARCHITECTURE.md section 6.1): a 32-byte header ("ADBL",
version 2, 48-bit FNV-1a hashes, 16-bit bucket prefix, entry count, CRC-32, build
time), a 65537-entry bucket table and the sorted 32-bit suffixes. MUST match
lib/core/blocklist/{hash,format}.h.

Usage: build_blocklist.py [--allow-missing] [--previous old.bin] [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 100k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt

Safety checks (audit 2026-11: the daily build trusted its third-party sources
completely, and the firmware blocks every subdomain of a listed name):
  - entries that would block a PROTECTED name (the update site, GitHub, the upstream
    DNS and NTP servers, big shared hosting) are dropped with a warning;
  - bare TLDs and second-level public suffixes (co.uk, com.au) are dropped;
  - more than MAX_ENTRIES names fails (the firmware refuses such a list);
  - with --previous, a count below half or above double the old list fails, so a
    truncated or bloated source can't replace a good list.
"""

import re
import struct
import sys, os, time, urllib.request, zlib

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
U64 = (1 << 64) - 1

# Format v2 (this firmware)
V2_HASH_BITS = 48
V2_PREFIX_BITS = 16
V2_MASK = (1 << V2_HASH_BITS) - 1
V2_BUCKETS = 1 << V2_PREFIX_BITS

# Default daily-driver list: ads + trackers + malware, WhatsApp/social keep working.
# ~100k entries (~0.65 MB in format v2). Hagezi's wildcard lists drop subdomains the
# firmware's parent matching already covers. Want more? pro-onlydomains.txt (~370k)
# fits easily (the firmware accepts up to 900k entries).
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",  # base: ads + malware
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",  # Hagezi Light (wildcard = domain + subdomains)
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r"^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$", re.I)

ALLOW_MISSING = False

# lib/core/blocklist/format.h kMaxListEntries: two lists must fit in LittleFS.
MAX_ENTRIES = 900_000

# Never blocked, nor any parent of them (the firmware's parent matching would block
# them through it): the board's update path and installer, the upstream resolvers and
# NTP, and shared hosting whose parent would take out large parts of the web.
PROTECTED = {
    "github.com",
    "api.github.com",
    "denzilrdz.github.io",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "registry.npmjs.org",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "pool.ntp.org",
    "time.cloudflare.com",
    "a.cloudfront.net",
    "a.amazonaws.com",
    "a.azureedge.net",
    "a.akamaized.net",
    "a.fastly.net",
    "a.appspot.com",
    "a.herokuapp.com",
    "a.pages.dev",
    "a.workers.dev",
    "a.googleusercontent.com",
    "www.google.com",
    "www.apple.com",
    "www.microsoft.com",
}

# Widely used second-level public suffixes: listing one would block a whole country's
# companies. An explicit set, not a pattern: lists deliberately block abused
# free-subdomain hosts that look alike (co.cc, co.nf).
PUBLIC_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "nhs.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "co.nz",
    "org.nz",
    "govt.nz",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "go.kr",
    "co.in",
    "net.in",
    "org.in",
    "gov.in",
    "ac.in",
    "nic.in",
    "co.za",
    "org.za",
    "gov.za",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.mx",
    "gob.mx",
    "com.ar",
    "gob.ar",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "com.hk",
    "com.tw",
    "com.sg",
    "gov.sg",
    "com.my",
    "com.ph",
    "com.tr",
    "gov.tr",
    "co.id",
    "go.id",
    "co.il",
    "gov.il",
    "com.sa",
    "com.eg",
    "com.pk",
    "com.ng",
    "co.ke",
    "com.vn",
    "co.th",
    "com.ua",
}


def is_public_suffix(d: str) -> bool:
    return "." not in d or d in PUBLIC_SUFFIXES


def blocks_protected(d: str) -> bool:
    """True if listing d would block a protected name (d is it, or a parent of it)."""
    return any(p == d or p.endswith("." + d) for p in PROTECTED)


def warn(msg: str) -> None:
    # A GitHub Actions annotation shows on the workflow run's summary page.
    print(
        ("::warning::" if os.environ.get("GITHUB_ACTIONS") else "warning: ") + msg,
        file=sys.stderr,
    )


def count_of(path: str) -> int:
    with open(path, "rb") as f:
        head = f.read(12)
    if len(head) < 12 or head[:4] != b"ADBL":
        raise ValueError(f"{path} is not a format v2 blocklist")
    return struct.unpack_from("<I", head, 8)[0]


def fnv64(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h


def hash48(name: str) -> int:
    """v2 hash: FNV-1a 64 truncated to 48 bits. Must match lib/core/blocklist/hash.h."""
    return fnv64(name.encode()) & V2_MASK


def norm(d: str) -> str:
    return d.strip().lower().lstrip("*").lstrip(".").rstrip(".")


def encode_v2(domains, build_time=None) -> bytes:
    """Serialises a set of domain names into format v2."""
    hashes = sorted({hash48(d) for d in domains})
    starts = [0] * (V2_BUCKETS + 1)
    for h in hashes:
        starts[(h >> 32) + 1] += 1
    for b in range(1, V2_BUCKETS + 1):
        starts[b] += starts[b - 1]
    payload = struct.pack("<%dI" % (V2_BUCKETS + 1), *starts)
    payload += struct.pack("<%dI" % len(hashes), *[h & 0xFFFFFFFF for h in hashes])
    header = struct.pack(
        "<4sBBBBIIq8x",
        b"ADBL",
        2,
        V2_HASH_BITS,
        V2_PREFIX_BITS,
        0,
        len(hashes),
        zlib.crc32(payload) & 0xFFFFFFFF,
        int(time.time() if build_time is None else build_time),
    )
    return header + payload


def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors="ignore").read()
    print(f"  downloading {src} ...", file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode("utf-8", "ignore")


def main():
    global ALLOW_MISSING
    argv = sys.argv[1:]
    previous = None
    if "--previous" in argv:
        i = argv.index("--previous")
        previous = argv[i + 1]
        del argv[i : i + 2]
    args = [a for a in argv if a != "--allow-missing"]
    ALLOW_MISSING = "--allow-missing" in argv
    out = args[0] if args else "blocklist.bin"
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f"  !! FAILED to read {src}: {e}", file=sys.stderr)
            if not ALLOW_MISSING:
                sys.exit(1)
            continue
        for line in data.splitlines():
            line = (
                line.split("#", 1)[0].strip()
                if not line.lstrip().startswith(("||", "@@"))
                else line.strip()
            )
            if not line or line[0] in "!/[":
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(
                    3
                ):  # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1
                    continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(("||", "@@", "|")) or any(c in line for c in "^$*"):
                skipped += 1
                continue  # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if "." in d and " " not in d:
                    domains.add(d)
    if allow:
        before = len(domains)
        domains -= allow
        print(
            f"allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)",
            file=sys.stderr,
        )
    if skipped:
        print(
            f"skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)",
            file=sys.stderr,
        )
    suffixes = sorted(d for d in domains if is_public_suffix(d))
    unsafe = sorted(d for d in domains if blocks_protected(d))
    for d in suffixes:
        warn(f"dropped {d}: a TLD or public suffix would block every site under it")
    for d in unsafe:
        warn(
            f"dropped {d}: it would block a protected name (update site, DNS, NTP, hosting)"
        )
    domains -= set(suffixes) | set(unsafe)

    hashes = [hash48(d) for d in domains]
    n = len(set(hashes))
    if n > MAX_ENTRIES:
        print(
            f"  !! {n:,} entries: more than the firmware accepts ({MAX_ENTRIES:,})",
            file=sys.stderr,
        )
        sys.exit(1)
    if previous:
        old = count_of(previous)
        if old and not (old / 2 <= n <= old * 2):
            print(
                f"  !! {n:,} entries vs {old:,} in {previous}: a change that large looks like a "
                "broken or tampered source; not replacing the list",
                file=sys.stderr,
            )
            sys.exit(1)
    blob = encode_v2(domains)
    collisions = len(hashes) - len(set(hashes))
    with open(out, "wb") as f:
        f.write(blob)

    print(f"source domains   : {len(domains):,}")
    print(f"hash entries     : {n:,}  ({V2_HASH_BITS}-bit)")
    print(f"collisions       : {collisions}  (domains sharing a hash -> over-block)")
    print(
        f"file             : {len(blob):,} bytes  ({len(blob) / 1024 / 1024:.2f} MB)  -> {out}"
    )


if __name__ == "__main__":
    main()
