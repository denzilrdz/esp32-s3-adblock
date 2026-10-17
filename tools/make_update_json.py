#!/usr/bin/env python3
"""Write update.json for the dashboard's "Check for updates" (published to GitHub Pages
next to the firmware by .github/workflows/release.yml).

The dashboard compares "version" with the running firmware, downloads "firmware"
(relative to update.json) into browser memory, checks its size and uploads it to the
device through the normal firmware upload.

Compatibility fields (read by every dashboard since v0.1.3, so they must stay
backwards compatible):
  schema         format of this file; a dashboard refuses a schema it doesn't know.
  minUpdateFrom  oldest running version allowed to install this release from the
                 dashboard. Raise it (installer/min-update-from) when a release can't
                 be installed over the air from older versions, e.g. a new partition
                 table or a settings format older firmware can't migrate.

Usage: make_update_json.py [--min-update-from X.Y.Z] <firmware.bin> <vX.Y.Z> <out.json>
                           [release-url]
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = 1
FIRMWARE_NAME = "firmware-esp32s3.bin"  # file name on the update site
ESP_IMAGE_MAGIC = 0xE9
_VERSION = re.compile(r"\d+\.\d+\.\d+")


def _version(v: str, what: str) -> tuple:
    v = v[1:] if v.startswith("v") else v
    if not _VERSION.fullmatch(v):
        raise ValueError(f"{what} must be X.Y.Z, got {v!r}")
    return v, tuple(int(n) for n in v.split("."))


def build(
    firmware: bytes, version: str, release_url: str = "", min_update_from: str = "0.0.0"
) -> dict:
    version, ver = _version(version, "version")
    min_update_from, minv = _version(min_update_from, "min-update-from")
    if minv > ver:
        raise ValueError(f"min-update-from {min_update_from} is newer than {version}")
    if not firmware or firmware[0] != ESP_IMAGE_MAGIC:
        raise ValueError("not an ESP32 app image (first byte must be 0xE9)")
    info = {
        "schema": SCHEMA,
        "version": version,
        "minUpdateFrom": min_update_from,
        "firmware": FIRMWARE_NAME,
        "size": len(firmware),
        "sha256": hashlib.sha256(firmware).hexdigest(),
    }
    if release_url:
        info["release"] = release_url
    return info


def main(argv):
    p = argparse.ArgumentParser(description="Write update.json for the dashboard.")
    p.add_argument("--min-update-from", default="0.0.0")
    p.add_argument("firmware")
    p.add_argument("version")
    p.add_argument("out")
    p.add_argument("release_url", nargs="?", default="")
    a = p.parse_args(argv[1:])
    try:
        info = build(
            Path(a.firmware).read_bytes(), a.version, a.release_url, a.min_update_from
        )
    except ValueError as e:
        print(f"make_update_json: {e}", file=sys.stderr)
        return 1
    Path(a.out).write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
