import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from make_update_json import FIRMWARE_NAME, SCHEMA, build

SCRIPT = pathlib.Path(__file__).with_name("make_update_json.py")
IMAGE = bytes([0xE9]) + b"\x00" * 1023


class BuildTest(unittest.TestCase):
    def test_fields(self):
        info = build(IMAGE, "v0.1.2", "https://example.org/releases/tag/v0.1.2")
        self.assertEqual(info["version"], "0.1.2")  # tag "v" stripped
        self.assertEqual(info["firmware"], FIRMWARE_NAME)
        self.assertEqual(info["size"], len(IMAGE))
        self.assertEqual(info["sha256"], hashlib.sha256(IMAGE).hexdigest())
        self.assertEqual(info["release"], "https://example.org/releases/tag/v0.1.2")

    def test_compatibility_fields(self):
        info = build(IMAGE, "v0.2.1", min_update_from="v0.2.0")
        self.assertEqual(info["schema"], SCHEMA)
        self.assertEqual(info["minUpdateFrom"], "0.2.0")
        self.assertEqual(
            build(IMAGE, "0.1.3")["minUpdateFrom"], "0.0.0"
        )  # default: any
        self.assertEqual(
            build(IMAGE, "0.2.0", min_update_from="0.2.0")["minUpdateFrom"], "0.2.0"
        )

    def test_min_update_from_is_validated(self):
        for m in (
            "0.3.0",
            "1.0.0",
            "0.2.1",
            "0.2",
            "x",
        ):  # newer than the release, or malformed
            with self.subTest(m=m), self.assertRaises(ValueError):
                build(IMAGE, "0.2.0", min_update_from=m)

    def test_release_url_is_optional(self):
        self.assertNotIn("release", build(IMAGE, "0.1.2"))

    def test_rejects_bad_versions(self):
        for v in ("", "v", "0.1", "0.1.2-rc1", "1.2.3.4", "x.y.z"):
            with self.subTest(v=v), self.assertRaises(ValueError):
                build(IMAGE, v)

    def test_rejects_non_app_images(self):
        # e.g. the factory image starts with the bootloader, not with an app image;
        # both start with 0xE9, so only an empty or foreign file is caught here.
        for data in (b"", b"\x00" + IMAGE[1:], b"PK\x03\x04"):
            with self.subTest(data=data[:4]), self.assertRaises(ValueError):
                build(data, "0.1.2")


class CliTest(unittest.TestCase):
    def test_writes_json(self):
        with tempfile.TemporaryDirectory() as d:
            fw, out = pathlib.Path(d, "fw.bin"), pathlib.Path(d, "update.json")
            fw.write_bytes(IMAGE)
            subprocess.run(
                [sys.executable, str(SCRIPT), str(fw), "v0.1.2", str(out)], check=True
            )
            info = json.loads(out.read_text())
            self.assertEqual((info["version"], info["size"]), ("0.1.2", len(IMAGE)))

    def test_min_update_from_flag(self):
        with tempfile.TemporaryDirectory() as d:
            fw, out = pathlib.Path(d, "fw.bin"), pathlib.Path(d, "update.json")
            fw.write_bytes(IMAGE)
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--min-update-from",
                    "0.2.0",
                    str(fw),
                    "v0.2.0",
                    str(out),
                ],
                check=True,
            )
            self.assertEqual(json.loads(out.read_text())["minUpdateFrom"], "0.2.0")

    def test_fails_on_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            fw = pathlib.Path(d, "fw.bin")
            fw.write_bytes(b"not firmware")
            r = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(fw),
                    "v0.1.2",
                    str(pathlib.Path(d, "u.json")),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn("not an ESP32 app image", r.stderr)
            self.assertFalse(pathlib.Path(d, "u.json").exists())


if __name__ == "__main__":
    unittest.main()
