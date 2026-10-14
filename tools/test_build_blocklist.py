import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from build_blocklist import hash48

SCRIPT = pathlib.Path(__file__).with_name("build_blocklist.py")


def run_builder(root, text, *flags):
    source = root / "hosts"
    output = root / "blocklist.bin"
    source.write_text(text, encoding="utf-8")
    subprocess.run(
        [sys.executable, str(SCRIPT), *flags, str(output), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
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


if __name__ == "__main__":
    unittest.main()
