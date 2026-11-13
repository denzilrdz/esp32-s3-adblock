#!/usr/bin/env python3
"""Build the dashboard demo for GitHub Pages (stdlib only).

    python3 tools/build_demo.py <out-dir> <version>

Takes the real dashboard from src/web/page.h, so the demo is always the page the
firmware serves, and writes into <out-dir>:

  index.html  the dashboard, plus a demo banner and a strict CSP
  app.js      its script, moved out of the page (Pages CSP: script-src 'self')
  api.js      installer/demo/api.js: a simulated device that answers /api/* in the
              browser, loaded first; __VERSION__ becomes <version>

Called by tools/build_site.sh (release.yml, pages.yml).
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'"
)

BANNER_CSS = (
    ".demo{background:var(--accent);color:var(--accent-ink);font-size:14px;padding:8px 16px;"
    "text-align:center;line-height:1.4}.demo a{color:inherit;font-weight:650}"
)

BANNER = (
    "<div class=demo role=note><b>Demo</b> · simulated data in your browser, "
    "no device behind it. Any user name and password logs in. "
    '<a href="../">Install AdBlock on an ESP32-S3 →</a></div>'
)


def dashboard() -> str:
    src = (ROOT / "src/web/page.h").read_text(encoding="utf-8")
    m = re.search(r'R"HTML\((.*)\)HTML"', src, re.S)
    if not m:
        raise SystemExit("kPage raw string not found in src/web/page.h")
    return m.group(1)


def build(out: pathlib.Path, version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"bad version: {version}")
    html = dashboard()
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    if len(scripts) != 1:
        raise SystemExit(
            f"expected one inline script in the dashboard, found {len(scripts)}"
        )

    def swap(old: str, new: str) -> None:
        nonlocal html
        if html.count(old) != 1:
            raise SystemExit(
                f"dashboard markup changed: {old!r} not found exactly once"
            )
        html = html.replace(old, new)

    swap(
        "<script>" + scripts[0] + "</script>",
        "<script src=api.js></script><script src=app.js></script>",
    )
    swap(
        "<head><meta charset=utf-8>",
        '<head><meta charset=utf-8><meta http-equiv=Content-Security-Policy content="'
        + CSP
        + '">',
    )
    swap("<title>AdBlock</title>", "<title>AdBlock dashboard demo</title>")
    swap("</style>", BANNER_CSS + "</style>")
    swap("<body data-auth=wait>", "<body data-auth=wait>" + BANNER)

    api = (ROOT / "installer/demo/api.js").read_text(encoding="utf-8")
    if api.count("__VERSION__") != 1:
        raise SystemExit("installer/demo/api.js: __VERSION__ placeholder missing")
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(html, encoding="utf-8")
    (out / "app.js").write_text(scripts[0].strip() + "\n", encoding="utf-8")
    (out / "api.js").write_text(api.replace("__VERSION__", version), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    build(pathlib.Path(sys.argv[1]), sys.argv[2])
