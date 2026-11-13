// Simulated device API for the dashboard demo on GitHub Pages (tools/build_demo.py).
//
// Loaded before the real dashboard script (src/web/page.h, unchanged), it answers the
// page's fetch('/api/...') calls in the browser, so the demo always shows the dashboard
// the firmware ships. Nothing leaves the browser. The traffic model follows a household
// of about ten devices: quiet nights, busy evenings, ~20 % blocked, bursts when an app
// opens. State lives in sessionStorage so a reload continues where it left off.
"use strict";
(() => {
  const VERSION = "__VERSION__";
  const KEY = "demo.state";
  const realFetch = window.fetch.bind(window);
  const MIN = 60000;

  // ---- traffic model --------------------------------------------------------------
  // Queries per minute for each local hour (a home: TVs and phones in the evening).
  const HOURLY = [12, 9, 8, 7, 8, 10, 18, 32, 42, 36, 34, 36, 40, 38, 36, 38, 44, 52, 64, 72, 76, 68, 44, 24];
  const hash = (n) => {
    const x = Math.sin(n * 12.9898) * 43758.5453;
    return x - Math.floor(x);
  };
  function hourly(t) {
    const d = new Date(t),
      h = d.getHours() + d.getMinutes() / 60,
      i = Math.floor(h),
      f = h - i;
    return HOURLY[i] * (1 - f) + HOURLY[(i + 1) % 24] * f;
  }
  // A burst (an app or a TV starting up) in some 10-minute windows: tracker heavy.
  function burst(t) {
    const w = Math.floor(t / (10 * MIN));
    if (hash(w) > 0.55) return 0;
    const c = (w + 0.15 + 0.7 * hash(w + 0.5)) * 10 * MIN,
      dx = (t - c) / (1.2 * MIN);
    return (1.2 + 2.2 * hash(w + 0.25)) * Math.exp(-dx * dx);
  }
  function rate(t) {
    const s = t / MIN,
      wobble = 1 + 0.18 * Math.sin(s / 7.3) + 0.12 * Math.sin(s / 2.1 + 1) + 0.08 * Math.sin(s * 1.37 + 2);
    return Math.max(0.5, hourly(t) * (wobble + burst(t)));
  }
  function blockShare(t) {
    const s = t / MIN;
    return Math.min(0.6, 0.2 + 0.05 * Math.sin(s / 13) + 0.03 * Math.sin(s / 3.1) + 0.08 * burst(t));
  }

  const CLIENTS = [
    ["192.168.1.10", "3c:22:fb:91:0a:4e", 14, 0.16],
    ["192.168.1.11", "f0:18:98:6c:21:d3", 17, 0.24],
    ["192.168.1.12", "a4:83:e7:3b:5f:90", 12, 0.22],
    ["192.168.1.20", "00:11:32:7a:c4:08", 4, 0.03],
    ["192.168.1.23", "b8:27:eb:19:e2:61", 6, 0.08],
    ["192.168.1.31", "64:1c:ae:52:9d:17", 21, 0.41],
    ["192.168.1.32", "dc:a6:32:8e:40:bb", 9, 0.33],
    ["192.168.1.40", "50:ec:50:0d:77:2a", 7, 0.47],
    ["192.168.1.41", "d8:f1:5b:63:0c:e5", 5, 0.58],
    ["192.168.1.47", "cc:50:e3:a1:3f:72", 3, 0.71],
  ];

  function upstreamList(cfg) {
    const prov = [cfg.up_pri, cfg.up_sec].filter((p, i, a) => p !== "none" && a.indexOf(p) === i);
    const out = [];
    for (const p of prov) out.push([p + "-dot", true], [p + "-dot-2", true]);
    if (cfg.up_doh)
      for (const p of prov) if (p === "cloudflare") out.push([p + "-doh", true], [p + "-doh-2", true]);
    if (cfg.up_plain) for (const p of prov) out.push([p + "-udp", false]);
    return out.map(([name, encrypted], i) => ({
      name,
      encrypted,
      state: i === 0 || (i === 2 && /-dot$/.test(name)) ? "up" : "unknown",
      ok: 0,
      failed: 0,
      latencyMs: 0,
      w: i === 0 ? 0.985 : 0.015,
    }));
  }

  function fresh(now) {
    const cfg = {
      up_pri: "cloudflare",
      up_sec: "quad9",
      up_doh: true,
      up_plain: true,
      up_cip: "",
      up_cip2: "",
      up_cname: "",
      up_cdoh: false,
      pad: true,
      ad: true,
      blk_ttl: 10,
      ff_canary: true,
      icloud: false,
      priv_rev: true,
      tz: "UTC0",
      log: 2,
      rb_mode: "weekly",
      rb_day: 0,
      rb_time: "04:00",
    };
    const day = new Date(now);
    day.setHours(2, 4, 0, 0);
    if (day > now) day.setDate(day.getDate() - 1);
    const st = {
      t: now - (3 * 1440 + 7 * 60 + 42) * MIN,
      boot: now - (3 * 1440 + 7 * 60 + 42) * MIN,
      restart: "power on",
      n: { q: 0, b: 0, tcp: 0, local: 0, cache: 0, fwd: 0, fail: 0, rw: 0 },
      clients: CLIENTS.map(([ip, mac, w, br]) => ({
        ip,
        mac,
        w,
        br,
        a: 0,
        b: 0,
        banned: ip === "192.168.1.47",
      })),
      ups: upstreamList(cfg),
      cfg,
      pauseUntil: 0,
      paused: false,
      cacheEntries: 0,
      testUntil: 0,
      rules: {
        block: ["metrics.roku.com", "telemetry.smart-plug.example"],
        allow: ["s.youtube.com", "click.redditmail.com"],
      },
      rewrites: [
        { d: "nas.home", t: "192.168.1.20", k: "ipv4", end: now + 7 * 60 * MIN },
        { d: "*.dev.home", t: "192.168.1.23", k: "ipv4", end: now + 42 * MIN },
        { d: "staging.example.com", t: "test-box.home", k: "alias", end: now + 17 * MIN },
      ],
      bl: {
        entries: 389214,
        built: day.getTime() - 34 * MIN,
        lastAttempt: day.getTime(),
        lastOk: true,
        lastResult: "updated",
        url: "https://github.com/denzilrdz/esp32-s3-adblock/releases/download/blocklist/blocklist.bin",
        time: "02:00",
      },
      out: false,
    };
    return st;
  }

  // Moves the simulation forward to `to` in steps of up to 4 s, calling `onStep` after each.
  function advance(st, to, onStep) {
    const n = st.n;
    while (st.t < to) {
      const dt = Math.min(4000, to - st.t),
        t = st.t + dt / 2;
      if (st.paused && st.pauseUntil && t >= st.pauseUntil) st.paused = false;
      const q = (rate(t) * dt) / MIN,
        bs = st.paused ? 0 : blockShare(t),
        b = q * bs,
        rest = q - b;
      n.q += q;
      n.b += b;
      n.tcp += q * 0.004;
      n.local += rest * 0.03;
      n.rw += rest * 0.006;
      n.cache += rest * 0.58;
      n.fwd += rest * 0.387;
      n.fail += rest * 0.0025;
      st.cacheEntries = Math.min(4000, st.cacheEntries + rest * 0.6 - st.cacheEntries * (dt / (90 * MIN)));
      const live = st.clients.filter((c) => !c.banned),
        wa = live.reduce((s, c) => s + c.w * (1 - c.br), 0),
        wb = live.reduce((s, c) => s + c.w * c.br, 0);
      for (const c of live) {
        c.a += (rest * c.w * (1 - c.br)) / wa;
        c.b += (b * c.w * c.br) / wb;
      }
      const fwd = rest * 0.387,
        upNow = st.ups.filter((u) => u.state === "up");
      for (const u of upNow) {
        u.ok += fwd * u.w * 0.9993;
        u.failed += fwd * u.w * 0.0007;
        const base = /doh/.test(u.name) ? 38 : /quad9/.test(u.name) ? 27 : 19;
        u.latencyMs = Math.round(
          base + 9 * hash(Math.floor(st.t / 4000) + u.name.length) + (burst(t) > 1 ? 14 : 0),
        );
      }
      st.t += dt;
      if (onStep) onStep(st);
    }
  }

  // ---- state ----------------------------------------------------------------------
  let st = null;
  try {
    st = JSON.parse(sessionStorage.getItem(KEY) || "null");
  } catch (e) {}
  if (!st || !st.n) {
    const now = Date.now();
    st = fresh(now);
    // Fill the browser-side history the dashboard keeps, so the live chart and the
    // latency sparklines start with the last 30 minutes instead of "Collecting data…".
    const hist = [],
      lat = {};
    let next = now - 30 * MIN;
    advance(st, now, (s) => {
      if (s.t < next) return;
      next += 4000;
      hist.push({ t: s.t, q: Math.floor(s.n.q), b: Math.floor(s.n.b) });
      if (now - s.t < 160000)
        for (const u of s.ups.filter((u) => u.state === "up"))
          (lat[u.name] = lat[u.name] || []).push(u.latencyMs);
    });
    try {
      sessionStorage.setItem("ab.hist", JSON.stringify({ s: hist, l: lat }));
    } catch (e) {}
  }
  const save = () => {
    try {
      sessionStorage.setItem(KEY, JSON.stringify(st));
    } catch (e) {}
  };

  // ---- formatting -----------------------------------------------------------------
  const p2 = (n) => String(n).padStart(2, "0");
  const stamp = (t) => {
    if (!t) return "never";
    const d = new Date(t);
    return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
  };
  function uptime(ms) {
    const s = Math.floor(ms / 1000);
    return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  }
  function nextReboot(cfg, now) {
    if (cfg.rb_mode === "off") return { mode: "off", next: "", nextDay: -1 };
    const [h, m] = cfg.rb_time.split(":").map(Number),
      d = new Date(now);
    d.setHours(h, m, 0, 0);
    while (d <= now || (cfg.rb_mode === "weekly" && d.getDay() !== Number(cfg.rb_day)))
      d.setDate(d.getDate() + 1);
    return { mode: cfg.rb_mode, next: stamp(d.getTime()), nextDay: d.getDay() };
  }
  const f = Math.floor;

  function stats(now) {
    advance(st, now);
    if (st.paused && st.pauseUntil && now >= st.pauseUntil) st.paused = false;
    st.rewrites = st.rewrites.filter((r) => r.end > now);
    if (st.testUntil && now >= st.testUntil) {
      st.testUntil = 0;
      for (const u of st.ups) {
        const base = /udp/.test(u.name) ? 11 : /doh/.test(u.name) ? 41 : /quad9/.test(u.name) ? 29 : 18;
        u.test = { result: "ok", ms: Math.round(base + 12 * Math.random()), rcode: 0, tlsError: 0 };
      }
    }
    const n = st.n,
      jitter = (a, b) => a + Math.round((b - a) * hash(f(now / 4000)));
    save();
    return {
      version: VERSION,
      hostname: "s3adblock",
      updateUrl: new URL("../", location.href).href,
      ip: "192.168.1.53",
      rssi: jitter(-61, -55),
      uptime: uptime(now - st.boot),
      heap: jitter(141000, 146500),
      heapMin: 97312,
      heapBlock: 69620,
      psram: 4392960 - f(st.cacheEntries) * 96,
      temp: Math.round(10 * (40.8 + 1.4 * hash(f(now / 60000)))) / 10,
      setupRequired: false,
      restart: {
        cause: st.restart === "power on" ? "power on" : "software",
        summary: st.restart,
        crash: null,
      },
      timeSynced: true,
      now: stamp(now),
      reboot: nextReboot(st.cfg, now),
      blocking: !st.paused,
      resumeIn: st.paused && st.pauseUntil ? Math.ceil((st.pauseUntil - now) / 1000) : 0,
      dns: {
        queries: f(n.q),
        tcp: f(n.tcp),
        blocked: f(n.b),
        local: f(n.local),
        cacheHits: f(n.cache),
        forwarded: f(n.fwd),
        servfail: f(n.fail),
        rewritten: f(n.rw),
        cacheEntries: f(st.cacheEntries),
      },
      plainFallback: false,
      upstreamTest: !!st.testUntil,
      upstreams: st.ups.map((u) => {
        const o = { name: u.name, encrypted: u.encrypted, state: u.state, ok: f(u.ok), failed: f(u.failed) };
        o.latencyMs = u.latencyMs;
        if (st.testUntil) o.test = { result: "pending", ms: 0, rcode: 0, tlsError: 0 };
        else if (u.test) o.test = u.test;
        return o;
      }),
      blocklist: {
        entries: st.bl.entries,
        inMemory: true,
        built: stamp(st.bl.built),
        lastAttempt: stamp(st.bl.lastAttempt),
        lastOk: st.bl.lastOk,
        lastResult: st.bl.lastResult,
        url: st.bl.url,
        time: st.bl.time,
      },
      rules: { block: st.rules.block.slice(), allow: st.rules.allow.slice() },
      rewrites: {
        max: 64,
        items: st.rewrites.map((r) => ({
          d: r.d,
          t: r.t,
          k: r.k,
          s: Math.max(0, f((r.end - now) / 1000)),
          wait: false,
        })),
      },
      clients: st.clients.map((c) => ({
        ip: c.ip,
        mac: c.mac,
        blocked: f(c.b),
        allowed: f(c.a),
        banned: c.banned,
      })),
    };
  }

  // A restart: counters, client table and cache start over, like on the board.
  function restart(why, now) {
    advance(st, now);
    st.boot = now;
    st.restart = "restarted by the firmware: " + why;
    for (const k in st.n) st.n[k] = 0;
    for (const c of st.clients) c.a = c.b = 0;
    st.cacheEntries = 0;
    st.paused = false;
    st.pauseUntil = 0;
    const old = st.ups;
    st.ups = upstreamList(st.cfg);
    for (const u of st.ups) {
      const o = old.find((x) => x.name === u.name);
      if (o && o.test) u.test = o.test;
    }
  }

  // ---- request handling -----------------------------------------------------------
  const text = (body, status = 200, headers = {}) =>
    new Response(body, { status, headers: Object.assign({ "Content-Type": "text/plain" }, headers) });
  const json = (o) =>
    new Response(JSON.stringify(o), { status: 200, headers: { "Content-Type": "application/json" } });
  const domainOk = (d) => /^(\*\.)?([a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$/i.test(d) && d.length <= 253;
  const ipv4 = (s) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);

  async function handle(path, method, body) {
    const now = Date.now();
    if (method === "GET") {
      if (st.out) return text("login required", 401);
      if (path === "/api/stats") return json(stats(now));
      if (path === "/api/config") return json(st.cfg);
      if (path === "/api/settings/export") {
        const out = {
          format: "adblock-settings",
          version: 1,
          config: st.cfg,
          blocklist: { url: st.bl.url, time: st.bl.time },
          rules: st.rules,
          banned: st.clients.filter((c) => c.banned).map((c) => c.ip),
        };
        return new Response(JSON.stringify(out, null, 2), {
          headers: {
            "Content-Type": "application/json",
            "Content-Disposition": 'attachment; filename="adblock-settings-demo.json"',
          },
        });
      }
      return text("not found", 404);
    }
    const a = body instanceof URLSearchParams ? body : new URLSearchParams();
    if (path === "/api/login") {
      if (!a.get("user") || !a.get("pass")) return text("wrong user name or password", 401);
      st.out = false;
      save();
      return text("ok");
    }
    if (path === "/api/logout") {
      st.out = true;
      save();
      return text("logged out");
    }
    if (st.out) return text("login required", 401);
    advance(st, now);
    let msg = "ok",
      code = 200;
    switch (path) {
      case "/api/blocking/pause": {
        const s = Number(a.get("s")) || 0;
        st.paused = true;
        st.pauseUntil = s ? now + s * 1000 : 0;
        msg = s ? "blocking paused" : "blocking paused until resumed";
        break;
      }
      case "/api/blocking/resume":
        st.paused = false;
        st.pauseUntil = 0;
        msg = "blocking resumed";
        break;
      case "/api/rules/add":
      case "/api/rules/remove": {
        const list = st.rules[a.get("list")],
          d = (a.get("d") || "").trim().toLowerCase().replace(/\.$/, "");
        if (!list || !domainOk(d) || d.startsWith("*.")) {
          code = 400;
          msg = "invalid domain";
        } else if (path.endsWith("add")) {
          if (!list.includes(d)) list.push(d);
          msg = "added";
        } else {
          const i = list.indexOf(d);
          if (i >= 0) list.splice(i, 1);
          msg = "removed";
        }
        break;
      }
      case "/api/rewrites/add": {
        const d = (a.get("d") || "").trim().toLowerCase(),
          t = (a.get("t") || "").trim(),
          m = Number(a.get("m")) || 60;
        const k = ipv4(t)
          ? "ipv4"
          : t.includes(":")
            ? "ipv6"
            : domainOk(t) && !t.startsWith("*.")
              ? "alias"
              : "";
        if (!domainOk(d) || !k) {
          code = 400;
          msg = !domainOk(d) ? "invalid domain" : "invalid answer";
          break;
        }
        // Same name again replaces it; a name holds one IPv4 and one IPv6, or one alias.
        st.rewrites = st.rewrites.filter(
          (r) => !(r.d === d && (r.k === k || r.k === "alias" || k === "alias")),
        );
        if (st.rewrites.length >= 64) {
          code = 409;
          msg = "rewrite table full";
          break;
        }
        st.rewrites.push({ d, t, k, end: now + m * MIN });
        msg = "rewrite added";
        break;
      }
      case "/api/rewrites/remove":
        st.rewrites = st.rewrites.filter((r) => !(r.d === a.get("d") && r.t === a.get("t")));
        msg = "rewrite removed";
        break;
      case "/api/clients/ban": {
        const c = st.clients.find((x) => x.ip === a.get("ip"));
        if (!c) {
          code = 400;
          msg = "invalid IP";
        } else {
          c.banned = !c.banned;
          msg = c.banned ? "banned" : "unbanned";
        }
        break;
      }
      case "/api/upstreams/test":
        st.testUntil = now + 2600;
        msg = "testing every upstream; results appear under Upstream DNS";
        break;
      case "/api/cache/flush":
        st.cacheEntries = 0;
        msg = "cache flushed";
        break;
      case "/api/blocklist/settings":
        if (a.get("u")) st.bl.url = a.get("u");
        if (/^\d\d:\d\d$/.test(a.get("t") || "")) st.bl.time = a.get("t");
        msg = "saved";
        break;
      case "/api/blocklist/update":
        st.bl.lastAttempt = now;
        st.bl.lastOk = true;
        st.bl.lastResult = "unchanged";
        msg = "update queued; result appears under Blocklist";
        break;
      case "/api/blocklist/upload":
        msg = "demo: the list stayed in your browser (a board would load it now)";
        break;
      case "/api/firmware":
        code = 400;
        msg = "demo: firmware installs are off here. Get the real thing from the installer page.";
        break;
      case "/api/config": {
        const next = Object.assign({}, st.cfg);
        for (const [k, v] of a) {
          if (!(k in next)) continue;
          next[k] = typeof next[k] === "boolean" ? v === "1" : typeof next[k] === "number" ? Number(v) : v;
        }
        const upChanged = ["up_pri", "up_sec", "up_doh", "up_plain"].some((k) => next[k] !== st.cfg[k]);
        st.cfg = next;
        if (upChanged) {
          restart("DNS settings changed", now);
          msg = "saved; restarting to apply DNS settings";
        } else msg = "saved";
        break;
      }
      case "/api/settings/import": {
        let ok = false;
        try {
          const file = body instanceof FormData ? body.get("f") : null,
            j = file ? JSON.parse(await file.text()) : null;
          if (j && typeof j === "object") {
            if (j.config) for (const k in j.config) if (k in st.cfg) st.cfg[k] = j.config[k];
            if (j.rules && Array.isArray(j.rules.block) && Array.isArray(j.rules.allow)) st.rules = j.rules;
            ok = true;
          }
        } catch (e) {}
        code = ok ? 200 : 400;
        msg = ok ? "settings imported" : "not a settings file";
        break;
      }
      case "/api/password":
        if ((a.get("next") || "").length < 10) {
          code = 400;
          msg = "new password: 10+ characters";
        } else msg = "demo: password changed (not stored anywhere)";
        break;
      case "/api/reboot":
        restart("rebooted from the dashboard", now);
        msg = "rebooting";
        break;
      case "/api/wifi/forget":
        msg = "demo: a real board would now reboot into its S3-AdBlock-XXXX setup network";
        break;
      default:
        code = 404;
        msg = "not found";
    }
    save();
    return text(msg, code);
  }

  window.fetch = function (input, init) {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith("/api/")) return realFetch(input, init);
    const method = ((init && init.method) || "GET").toUpperCase();
    // A short delay, like a request to the board over Wi-Fi.
    return new Promise((r) => setTimeout(r, 40 + 60 * Math.random())).then(() =>
      handle(url.pathname, method, init && init.body),
    );
  };
})();
