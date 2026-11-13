import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

import build_blocklist
from build_blocklist import hash48

SCRIPT = pathlib.Path(__file__).with_name("build_blocklist.py")


def run_builder(root, text, *flags, check=True):
    source = root / "hosts"
    output = root / "blocklist.bin"
    source.write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *flags, str(output), str(source)],
        check=check,
        capture_output=True,
        text=True,
    )
    if not check:
        return proc
    return output.read_bytes()


def parse_v2(data):
    magic, version, bits, prefix, flags, count, crc, built = struct.unpack_from(
        "<4sBBBBIIq", data
    )
    starts = struct.unpack_from("<65537I", data, 32)
    suffixes = struct.unpack_from("<%dI" % count, data, 32 + 4 * 65537)
    hashes = set()
    for bucket in range(65536):
        for i in range(starts[bucket], starts[bucket + 1]):
            hashes.add((bucket << 32) | suffixes[i])
    return dict(
        magic=magic,
        version=version,
        bits=bits,
        prefix=prefix,
        flags=flags,
        count=count,
        crc=crc,
        built=built,
        starts=starts,
        suffixes=suffixes,
        hashes=hashes,
    )


class BuildBlocklistTests(unittest.TestCase):
    def test_hash48_golden_values_match_firmware(self):
        # Same values as test/test_blocklist/test_main.cpp: change both together.
        self.assertEqual(hash48("ads.example.com"), 0x3158979AA55E)
        self.assertEqual(hash48("doubleclick.net"), 0x04CD127775CD)
        self.assertEqual(hash48("example.com"), 0x46634E2714C6)

    def test_v2_file_layout_header_and_crc(self):
        with tempfile.TemporaryDirectory() as directory:
            data = run_builder(
                pathlib.Path(directory),
                "0.0.0.0 ads.example.com tracker.example.com # comment\n"
                "127.0.0.1 metrics.example.com\n"
                "||adguard.example^\n@@||allowed.example^\n||allowed.example^\n"
                "www.keep-www.example\n",
            )
        f = parse_v2(data)
        self.assertEqual(f["magic"], b"ADBL")
        self.assertEqual(
            (f["version"], f["bits"], f["prefix"], f["flags"]), (2, 48, 16, 0)
        )
        self.assertEqual(len(data), 32 + 4 * 65537 + 4 * f["count"])
        self.assertEqual(f["crc"], zlib.crc32(data[32:]) & 0xFFFFFFFF)
        self.assertEqual(f["starts"][0], 0)
        self.assertEqual(f["starts"][-1], f["count"])
        expected = {
            hash48(d)
            for d in (
                "ads.example.com",
                "tracker.example.com",
                "metrics.example.com",
                "adguard.example",
                "www.keep-www.example",
            )
        }
        self.assertEqual(f["hashes"], expected)  # allow rule removed, www. kept in v2

    def test_v2_suffixes_sorted_within_buckets(self):
        names = "\n".join("d%d.example%d.com" % (i, i % 7) for i in range(3000))
        with tempfile.TemporaryDirectory() as directory:
            f = parse_v2(run_builder(pathlib.Path(directory), names))
        self.assertEqual(f["count"], 3000)
        self.assertEqual(len(f["hashes"]), 3000)
        for bucket in range(65536):
            run = f["suffixes"][f["starts"][bucket] : f["starts"][bucket + 1]]
            self.assertTrue(all(a < b for a, b in zip(run, run[1:])), bucket)

    def test_protected_names_and_their_parents_are_dropped(self):
        # Audit 2026-11: a listed github.io (a parent of the update site) would make
        # every board block its own update host and installer for the whole LAN.
        text = "\n".join(
            [
                "0.0.0.0 ads.example.com",
                "0.0.0.0 github.io",
                "0.0.0.0 denzilrdz.github.io",
                "||githubusercontent.com^",
                "0.0.0.0 cloudfront.net",
                "0.0.0.0 tracker.cloudfront.net",  # a subdomain: fine
                "||cloudflare-dns.com^",
                "0.0.0.0 ntp.org",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            f = parse_v2(run_builder(pathlib.Path(directory), text))
        self.assertEqual(
            f["hashes"], {hash48("ads.example.com"), hash48("tracker.cloudfront.net")}
        )

    def test_tlds_and_public_suffixes_are_dropped(self):
        text = "\n".join(
            [
                "||com^",
                "||co.uk^",
                "0.0.0.0 com.au",
                "0.0.0.0 ads.co.uk",
                "0.0.0.0 co.example",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            f = parse_v2(run_builder(pathlib.Path(directory), text))
        self.assertEqual(f["hashes"], {hash48("ads.co.uk"), hash48("co.example")})

    def test_protected_set_covers_the_device_dependencies(self):
        # The hosts the firmware itself depends on (config.cpp providers, main.cpp NTP,
        # dashboard.cpp UPDATE_BASE_URL): if one changes, extend PROTECTED.
        for name in (
            "cloudflare-dns.com",
            "dns.quad9.net",
            "pool.ntp.org",
            "denzilrdz.github.io",
        ):
            self.assertTrue(build_blocklist.blocks_protected(name), name)
        root = pathlib.Path(__file__).resolve().parent.parent
        dashboard = (root / "src/web/dashboard.cpp").read_text(encoding="utf-8")
        self.assertIn('"https://denzilrdz.github.io/esp32-s3-adblock/"', dashboard)
        config = (root / "lib/core/config/config.cpp").read_text(encoding="utf-8")
        self.assertIn('"cloudflare-dns.com"', config)
        self.assertIn('"dns.quad9.net"', config)

    def test_too_many_entries_fails(self):
        # Run the real main() with the limit lowered to 5.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            src, out = root / "hosts", root / "out.bin"
            src.write_text("\n".join("0.0.0.0 d%d.example.com" % i for i in range(6)))
            code = (
                "import sys; sys.path.insert(0, %r); import build_blocklist as b; "
                "b.MAX_ENTRIES = 5; sys.argv = ['b', %r, %r]; b.main()"
            ) % (str(SCRIPT.parent), str(out), str(src))
            proc = subprocess.run(
                [sys.executable, "-c", code], capture_output=True, text=True
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("more than the firmware accepts", proc.stderr)
            self.assertFalse(out.exists())
        # The limit matches the firmware's.
        fmt = (
            pathlib.Path(__file__).resolve().parent.parent
            / "lib/core/blocklist/format.h"
        ).read_text()
        self.assertIn("kMaxListEntries = %d;" % build_blocklist.MAX_ENTRIES, fmt)

    def test_partition_size_matches_the_firmware_constant(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        csv = (root / "partitions_16MB.csv").read_text()
        size = [
            l.split(",")[4].strip() for l in csv.splitlines() if l.startswith("spiffs")
        ][0]
        fmt = (root / "lib/core/blocklist/format.h").read_text()
        self.assertIn("kListPartitionBytes = %s;" % size, fmt)

    def test_a_large_change_against_the_previous_list_fails(self):
        names = "\n".join("0.0.0.0 d%d.example.com" % i for i in range(200))
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            prev = root / "prev.bin"
            prev.write_bytes(run_builder(root, names))
            # Same size: fine. A fifth of it (a truncated source): refused.
            run_builder(root, names, "--previous", str(prev))
            short = "\n".join("0.0.0.0 d%d.example.com" % i for i in range(40))
            proc = run_builder(root, short, "--previous", str(prev), check=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not replacing the list", proc.stderr)
            self.assertEqual(prev.read_bytes()[:4], b"ADBL")


if __name__ == "__main__":
    unittest.main()
