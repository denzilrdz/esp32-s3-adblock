#!/usr/bin/env python3
"""Write update.json for the dashboard's "Check for updates" (published to GitHub Pages
next to the firmware by .github/workflows/release.yml).

The dashboard compares "version" with the running firmware, downloads "firmware"
(relative to update.json) into browser memory, checks its size and uploads it to the
device through the normal firmware upload.

Usage: make_update_json.py <firmware.bin> <version, e.g. v0.1.2> <out.json> [release-url]
"""

import hashlib
import json
import re
import sys
from pathlib import Path

FIRMWARE_NAME = "firmware-esp32s3.bin"  # file name on the update site
ESP_IMAGE_MAGIC = 0xE9


def build(firmware: bytes, version: str, release_url: str = "") -> dict:
    version = version[1:] if version.startswith("v") else version
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"version must be X.Y.Z, got {version!r}")
    if not firmware or firmware[0] != ESP_IMAGE_MAGIC:
        raise ValueError("not an ESP32 app image (first byte must be 0xE9)")
    info = {
        "version": version,
        "firmware": FIRMWARE_NAME,
        "size": len(firmware),
        "sha256": hashlib.sha256(firmware).hexdigest(),
    }
    if release_url:
        info["release"] = release_url
    return info


def main(argv):
    if len(argv) not in (4, 5):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    firmware = Path(argv[1]).read_bytes()
    try:
        info = build(firmware, argv[2], argv[4] if len(argv) == 5 else "")
    except ValueError as e:
        print(f"make_update_json: {e}", file=sys.stderr)
        return 1
    Path(argv[3]).write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
