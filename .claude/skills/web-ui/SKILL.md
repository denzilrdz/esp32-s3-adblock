---
name: web-ui
description: Design system and rules for every web page of the project - the dashboard (src/web/page.h), the Wi-Fi setup portal (src/web/portal.cpp) and the GitHub Pages installer (installer/). Use before changing any of their HTML/CSS/JS, adding a chart, card, banner or setting, or styling a new page.
---

# Web UI

Three pages (plus a demo of the dashboard), one look. All are hand-written
HTML/CSS/vanilla JS with **no external resources** (no CDN, fonts, frameworks), because
the CSPs forbid them, the setup portal has no internet, and the dashboard lives in flash.

| Page         | File                    | Constraints                                                                                                                                                                                                                                                                               |
| ------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard    | `src/web/page.h`        | CSP `default-src 'self'` + update-site origin, inline script/style allowed. ≤ 64 KB (test). Login screen until `/api/stats` answers (session cookie); polls it every 4 s.                                                                                                                 |
| Setup portal | `src/web/portal.cpp`    | Opened by phones' captive mini-browsers (iOS CNA: little JS): **must work without JS**. Built with `String` (not the DNS hot path).                                                                                                                                                       |
| Installer    | `installer/index.html`  | CSP `script-src 'self'`: **no inline script**. `__VERSION__` is stamped by release.yml. esp-web-tools vendored and hash-checked. `404.html`.                                                                                                                                              |
| Demo         | `installer/demo/api.js` | The dashboard on Pages at `/demo/`, built by `tools/build_demo.py` from page.h (script moved to `app.js`, CSP `script-src 'self'`). `api.js` loads first and answers `/api/*` in the browser with simulated traffic: **a new dashboard endpoint or field needs a matching answer there**. |

`tools/test_web_pages.py` enforces size, no `innerHTML`, no external loads, no inline
script on Pages, and that the dashboard script parses (`node --check`).

## Principles (from the research behind the 2026-10 redesign)

- **Lead with the answer.** One hero number per view (block rate), then a row of
  stat tiles (label · value · context line · optional sparkline). A bare number is
  trivia: every tile gets a context line ("13% of queries", "254 answers cached").
- **Status = colour + dot/icon + words**, never colour alone (`blocking on`, `up`,
  `standby`). Status colours are reserved for state, never for series.
- **Act without asking.** Fetch what the page can know on load (e.g. the update check
  runs automatically; "Check again" only after a result). Confirm only destructive
  or rebooting actions (`confirm()` is fine on our pages).
- **Progressive disclosure.** Idle/standby items fold into `<details>` (standby
  upstreams, manual firmware upload). Help text sits under the control as `.hint`.
- **Phone first.** Single column below ~700 px, 16 px gutters, no horizontal page
  scroll (tables scroll inside `.tw`), tap targets ≥ 44 px on the portal/installer
  (≥ 34 px on the dense dashboard), `inputmode`/`autocomplete`/`autocapitalize=off`
  on technical inputs.
- **No new board features for UI.** Derive from existing endpoints. History for charts
  is kept in the browser (`sessionStorage`), never on the device.

## Tokens

Defined on `:root` with a dark override under
`@media (prefers-color-scheme:dark){:root:not([data-theme=light])…}` **and**
`:root[data-theme=dark]` (the dashboard's theme toggle; choice in `localStorage`
`ab.theme`, wrapped in try/catch). The portal/installer follow the OS only.

| Token                          | Light                             | Dark                              | Use                                  |
| ------------------------------ | --------------------------------- | --------------------------------- | ------------------------------------ |
| `--page`                       | `#f6f6f4`                         | `#0d0d0d`                         | body background                      |
| `--surface`                    | `#fcfcfb`                         | `#1a1a19`                         | cards, chart surface                 |
| `--raised`                     | `#f0efec`                         | `#242423`                         | buttons, chips, meter track          |
| `--line` / `--axis`            | `#e1e0d9` / `#c3c2b7`             | `#2c2c2a` / `#383835`             | hairlines / baselines, input borders |
| `--ink` / `--ink2` / `--muted` | `#0b0b0b` / `#52514e` / `#76746e` | `#f0efec` / `#c3c2b7` / `#9a988f` | text levels                          |
| `--accent`                     | `#256abf`                         | `#3987e5`                         | primary buttons, links, focus        |
| `--good` / `--warn` / `--bad`  | `#0ca30c` / `#fab219` / `#d03b3b` | same                              | status dots and banner edges         |

Brand: the green shield SVG + "AdBlock" in 650 weight. Font: `system-ui` stack only;
`tabular-nums` only in number columns, never on hero/tile values.

## Chart palette (validated)

Fixed entity → colour mapping, same everywhere (dashboard `--s-*` tokens):

| Entity    | Light     | Dark                            |
| --------- | --------- | ------------------------------- |
| allowed   | `#2a78d6` | `#3987e5`                       |
| blocked   | `#eb6834` | `#d95926`                       |
| cache     | `#1baf7a` | `#199e70`                       |
| forwarded | `#eda100` | `#c98500`                       |
| local     | `#e87ba4` | `#d55181`                       |
| other     | `#c3c2b7` | `#4a4a46` (neutral, not a slot) |

This order passes the colour-blind (CVD) and normal-vision separation checks in both
modes (dataviz skill validator: worst adjacent ΔE 9.1 light / 8.4 dark). In light mode
cache/forwarded/local fall below 3:1 contrast, so **values are always printed beside
them** (legend lists). A new entity takes the next slot (green `#008300`, violet
`#6250d6`/`#9085e9`), and you re-run the validator. Never repaint existing entities.

## Chart rules

- Hand-drawn SVG via `sv()` (`createElementNS`), never markup strings.
- Line: 2 px, round joins; area wash at 10 % opacity; end dot r = 4 with a 2 px
  `--surface` ring. Gridlines 1 px solid `--line`, baseline `--axis`, ≤ 5 ticks,
  compact labels (1.2K). **One y-axis only**: different units go in separate charts.
- Hover layer on every plot: crosshair + tooltip (pointer and touch), arrow keys
  when focused (`tabindex=0`), Esc clears. Tooltips only add detail: the current value
  is also shown in the legend.
- Legend for ≥ 2 series, with current values; text in ink tokens, never series colours.
- Part of whole: a horizontal stacked bar with 2 px gaps and 4 px rounded ends, plus a
  legend list (swatch · label · count · %). No pies/donuts.
- Sparklines: no axes, `--axis` stroke, accent end dot, ≥ 2 points or nothing.
- Empty state text ("Collecting data…") instead of an empty frame.
- Counters reset on reboot: detect a decrease and restart the history.

## Components (class names in page.h)

`.card` · `.tiles/.tile` · `.hero` · `.pill.is-good|warn|bad` with `.dot` ·
`.banner.bad|warn|info` (left edge + wash; `hidden` toggles it) · `.badge` ·
`.chips/.chip` (removable rules) · `.legend/.key/.sw/.ln` · `.stack` · `.blist` ·
`.meter` · `.kv` (definition list) · `.chk` (checkbox + label + `<small>` help) ·
`.fld` (label above input) · `button.primary|danger|ghost` · `#toast` (aria-live).

**Prefer dropdowns** for anything with a known set of values (times, durations, time
zones, TTLs): `tpInit(id)`/`tpSet(id,'HH:MM')`/`tpGet(id)` build a `.tp` hour + minute
picker (5-minute steps); a form field it feeds is a hidden input set on submit.
Fill selects from data with `setVal(select, v)`: it adds an option for a value the
list lacks (set by a script, an import or an older page) instead of silently showing
the first option and saving that. Time zones come from the `TZ` table in page.h (label |
POSIX string from the IANA database | IANA names, for the browser-zone shortcut);
verify new strings against nayarsystems/posix_tz_db `zones.csv`.

`[hidden]{display:none!important}` is required: component classes set `display`.

## Security (also security-checklist)

- Server data → `textContent`/`value`/attributes only. In C++ (portal) every scanned
  SSID goes through `htmlEscape`. Quote attribute values that may end in `/`:
  `fill=currentColor/>` parses as the colour `currentColor/` (use ` />`).
- Every change is a POST through `api()` (adds `X-Requested-With: adblock`). `api()`
  treats **any 401 as "session ended"** and logs the page out: a route that rejects a
  wrong value the user typed (e.g. the current password) answers 400, not 401.
- New dashboard routes: `route()` in `dashboard.cpp` (request-body limit), never
  `server.on()`. Form posts stay well under 8 KB; bigger data goes as a multipart
  file upload.
- New origins need a CSP change in `pageCsp()` (dashboard) or the installer `<meta>`:
  avoid. The dashboard CSP also sets `base-uri 'none'`, `form-action 'self'`,
  `object-src 'none'`; the installer's `frame-ancestors` in a `<meta>` tag is ignored
  by browsers (GitHub Pages can't send headers).

## Preview without a board

Extract the page and serve it with mocked data (copy a real `/api/stats` from the board:
`curl -u admin:<password> http://s3adblock.local/api/stats`):

```python
import re; html = re.search(r'R"HTML\((.*)\)HTML"', open("src/web/page.h").read(), re.S).group(1)
# serve html at /, the JSON at /api/stats and /api/config, POST -> 200 "ok"
```

The page starts on its login screen: answer `401` to `/api/*` until `POST /api/login`
succeeds, and set a cookie there that the mock then checks (or answer 200 from the start
to skip the login).

**README / link-preview images** (`docs/img/*.png`, `installer/social-preview.png`):
serve the page from such a mock with realistic numbers, seed the chart history in
`sessionStorage` (`ab.hist`) before the page script runs, and capture with headless
Chrome (`--headless=new --window-size=1280,960 --virtual-time-budget=4000
--screenshot=...`). Headless capture ignores scrolling: for one section, hide the
others with injected CSS. Then compress to a 256-colour palette with Pillow's
`FASTOCTREE` quantizer (keeps the chart colours exact; `MEDIANCUT` shifts them).

Set `updateUrl` in the mock to a local `update.json` with a higher version to see
the update states. Check desktop and ~390 px wide, light and dark, before committing.

Headless gotchas: the viewport is never narrower than **500 px** whatever
`--window-size` says, so check phone width by loading the mock in a 390 px `<iframe>`
from a local wrapper page. `--force-prefers-color-scheme` loses to the page's own theme
choice: for a light/dark capture, inject `localStorage.setItem('ab.theme','light')` at
the start of the page script. The tab highlight follows scrolling, so with other
sections hidden, set the active tab with injected CSS (`nav.tabs a[href="#settings"]`).
Pillow isn't in `.venv`: `uv run --no-project --with pillow python compress.py`.
