"""Guards for the web pages (skill web-ui): the dashboard in src/web/page.h, the setup
portal in src/web/portal.cpp and the installer site in installer/.

They check the rules a browser won't flag until it is too late: the flash size budget,
no innerHTML, nothing loaded from other sites (the CSPs forbid it, and the setup portal
has no internet), and that the dashboard script at least parses.
"""

import ast
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE_BUDGET = 64 * 1024  # bytes of flash for the dashboard page


def dashboard() -> str:
    src = (ROOT / "src/web/page.h").read_text(encoding="utf-8")
    m = re.search(r'R"HTML\((.*)\)HTML"', src, re.S)
    assert m, "kPage raw string not found"
    return m.group(1)


def portal_head() -> str:
    src = (ROOT / "src/web/portal.cpp").read_text(encoding="utf-8")
    block = src[src.index("kHead[] PROGMEM") : src.index("const char kLock")]
    return "".join(
        ast.literal_eval('"' + s + '"')
        for s in re.findall(r'"((?:[^"\\]|\\.)*)"', block)
    )


def external_loads(html: str) -> list:
    """src/href/url() references that would make the browser load another site."""
    refs = re.findall(
        r"""(?:\bsrc\s*=\s*|<link[^>]*href\s*=\s*|url\()\s*["']?(https?:)?//""",
        html,
        re.I,
    )
    return refs


class DashboardPageTest(unittest.TestCase):
    def setUp(self):
        self.html = dashboard()

    def test_fits_budget(self):
        self.assertLess(len(self.html.encode()), PAGE_BUDGET)

    def test_no_innerhtml_or_external_resources(self):
        self.assertNotIn("innerHTML", self.html)
        self.assertNotIn("outerHTML", self.html)
        self.assertNotIn("insertAdjacentHTML", self.html)
        self.assertEqual(external_loads(self.html), [])
        self.assertNotIn("<link", self.html)

    def test_every_change_goes_through_api(self):
        # api() is the only place that POSTs, and it always adds the CSRF header.
        self.assertEqual(self.html.count("method:'POST'"), 1)
        self.assertIn("'X-Requested-With':'adblock'", self.html)

    def test_light_and_dark_tokens(self):
        self.assertIn("prefers-color-scheme:dark", self.html)
        self.assertIn(":root[data-theme=dark]", self.html)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_script_parses(self):
        scripts = re.findall(r"<script>(.*?)</script>", self.html, re.S)
        self.assertEqual(len(scripts), 1)
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "page.js"
            f.write_text(scripts[0], encoding="utf-8")
            r = subprocess.run(
                ["node", "--check", str(f)], capture_output=True, text=True
            )
            self.assertEqual(r.returncode, 0, r.stderr)


class PortalPageTest(unittest.TestCase):
    def test_works_offline_without_script(self):
        head = portal_head()
        self.assertIn("<meta name=viewport", head)
        # iOS opens captive portals in a mini-browser: plain HTML forms, no script tags.
        self.assertNotIn("<script", head)
        self.assertEqual(external_loads(head), [])


class InstallerSiteTest(unittest.TestCase):
    def test_csp_safe(self):
        for name in ("index.html", "404.html"):
            html = (ROOT / "installer" / name).read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", html, name)
            # CSP is script-src 'self': inline scripts would be blocked.
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>", name)
            self.assertEqual(external_loads(html), [], name)

    def test_version_placeholder_is_stamped_by_release(self):
        html = (ROOT / "installer/index.html").read_text(encoding="utf-8")
        self.assertIn("__VERSION__", html)
        wf = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("installer/index.html > site/index.html", wf)
        self.assertIn("installer/404.html site/", wf)


if __name__ == "__main__":
    unittest.main()
