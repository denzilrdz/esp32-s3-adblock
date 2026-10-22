#pragma once
// Dashboard single page (served from flash). Security rules for this file:
//  - never put server data into innerHTML: build nodes, set textContent/value
//  - every change is a POST through api(), which adds X-Requested-With: adblock
//  - no external resources: the CSP only allows this device and the update site
// Design rules (tokens, charts, components): skill `web-ui`. The charts are drawn
// from /api/stats polls kept in this browser, so they need nothing new on the board.
// Kept in its own header so the Arduino IDE preprocessor doesn't choke on it.

#include <pgmspace.h>

namespace web {

const char kPage[] PROGMEM = R"HTML(<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><meta name=color-scheme content="light dark">
<title>AdBlock</title><style>
:root{color-scheme:light;--page:#f6f6f4;--surface:#fcfcfb;--raised:#f0efec;--line:#e1e0d9;--axis:#c3c2b7;
--ink:#0b0b0b;--ink2:#52514e;--muted:#76746e;--accent:#256abf;--accent-ink:#fff;--focus:#2a78d6;
--good:#0ca30c;--good-ink:#006300;--warn:#fab219;--warn-ink:#8a5a00;--bad:#d03b3b;--bad-ink:#b42323;
--bad-wash:#fbeaea;--warn-wash:#fdf3dc;--info-wash:#e8f0fb;
--s-allowed:#2a78d6;--s-blocked:#eb6834;--s-cache:#1baf7a;--s-fwd:#eda100;--s-local:#e87ba4;--s-other:#c3c2b7;
--r:10px;--shadow:0 1px 2px rgba(0,0,0,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--raised:#242423;
--line:#2c2c2a;--axis:#383835;--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a988f;--accent:#3987e5;--accent-ink:#06121f;--focus:#5598e7;
--good-ink:#3fc23f;--warn-ink:#fab219;--bad-ink:#f07070;--bad-wash:#2d1515;--warn-wash:#2b2210;--info-wash:#13202f;
--s-allowed:#3987e5;--s-blocked:#d95926;--s-cache:#199e70;--s-fwd:#c98500;--s-local:#d55181;--s-other:#4a4a46;--shadow:none}}
:root[data-theme=dark]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--raised:#242423;
--line:#2c2c2a;--axis:#383835;--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a988f;--accent:#3987e5;--accent-ink:#06121f;--focus:#5598e7;
--good-ink:#3fc23f;--warn-ink:#fab219;--bad-ink:#f07070;--bad-wash:#2d1515;--warn-wash:#2b2210;--info-wash:#13202f;
--s-allowed:#3987e5;--s-blocked:#d95926;--s-cache:#199e70;--s-fwd:#c98500;--s-local:#d55181;--s-other:#4a4a46;--shadow:none}
*{box-sizing:border-box}[hidden]{display:none!important}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}html{scroll-padding-top:104px}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}a:hover{text-decoration:none}code{background:var(--raised);padding:1px 5px;border-radius:4px;font-size:12.5px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.top{position:sticky;top:0;z-index:5;background:var(--surface);border-bottom:1px solid var(--line)}
.bar{max-width:1180px;margin:auto;padding:10px 16px;display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center}
.brand{display:flex;align-items:center;gap:8px;font-weight:650;font-size:17px;margin-right:auto}.brand svg{color:var(--good)}
.pills{display:flex;flex-wrap:wrap;gap:6px}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:99px;padding:3px 10px;font-size:12px;color:var(--ink2);background:var(--surface);text-decoration:none;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.is-good .dot{background:var(--good)}.is-warn .dot{background:var(--warn)}.is-bad .dot{background:var(--bad)}
a.pill.is-info{border-color:var(--accent);color:var(--accent)}
nav.tabs{max-width:1180px;margin:auto;padding:0 10px;display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}
nav.tabs a{padding:8px 10px;color:var(--ink2);text-decoration:none;border-bottom:2px solid transparent;font-weight:500;white-space:nowrap}
nav.tabs a:hover{color:var(--ink)}nav.tabs a.on{color:var(--ink);border-bottom-color:var(--accent)}
main{max-width:1180px;margin:auto;padding:12px 16px 72px}
section{padding-top:8px}
h2{font-size:15px;margin:22px 0 10px;font-weight:650}h3{font-size:13px;margin:0 0 8px;font-weight:600;color:var(--ink2)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;box-shadow:var(--shadow);min-width:0}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr))}
#cfg{grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr))}
.tiles{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-top:12px}
.tile .l{color:var(--ink2);font-size:12.5px}.tile .v{font-size:22px;font-weight:620;margin-top:2px}.tile .s{color:var(--muted);font-size:12px}
.tile svg{display:block;margin-top:6px;width:100%;height:28px}
.hero{display:flex;flex-wrap:wrap;gap:16px 28px;align-items:center;justify-content:space-between}
.hero .big{font-size:48px;font-weight:650;line-height:1}.hero .sub{color:var(--ink2);margin-top:6px}
.ctl{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
.seg{display:inline-flex;flex-wrap:wrap;gap:6px}
.banner{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:var(--r);padding:10px 14px;margin:0 0 10px;background:var(--surface)}
.banner.bad{border-left-color:var(--bad);background:var(--bad-wash)}.banner.warn{border-left-color:var(--warn);background:var(--warn-wash)}.banner.info{border-left-color:var(--accent);background:var(--info-wash)}
.banner p{margin:0;flex:1 1 320px}
button,input,select{font:inherit;color:var(--ink)}
button{background:var(--raised);border:1px solid var(--line);border-radius:8px;padding:7px 12px;cursor:pointer;min-height:34px}
button:hover{border-color:var(--axis)}button:disabled{opacity:.55;cursor:default}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
button.danger{color:var(--bad-ink)}button.ghost{background:none;border-color:transparent;color:var(--accent);padding:4px 6px;min-height:0}
button.on{border-color:var(--accent);color:var(--accent);font-weight:600}
input,select{background:var(--surface);border:1px solid var(--axis);border-radius:8px;padding:7px 10px;min-height:34px;min-width:0}
input[type=checkbox]{min-height:0;width:16px;height:16px;accent-color:var(--accent)}input[type=file]{border-style:dashed;max-width:100%}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}.row>input:not([type=checkbox]){flex:1 1 160px}
.hint{color:var(--muted);font-size:12.5px}.ink2{color:var(--ink2)}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12.5px;color:var(--ink2);margin:0 0 6px}
.key{display:inline-flex;align-items:center;gap:6px}.sw{width:10px;height:10px;border-radius:3px;flex:none}.ln{width:14px;height:2px;border-radius:1px;flex:none}
.key b{color:var(--ink);font-weight:600}
.chart{position:relative}.chart svg{display:block;width:100%;overflow:visible}.chart:focus-visible{outline-offset:4px}
.empty{color:var(--muted);text-align:center;padding:52px 8px}
#tip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:12px;box-shadow:0 4px 14px rgba(0,0,0,.18);white-space:nowrap;display:none;z-index:2}
#tip .t{color:var(--muted);margin-bottom:2px}
.stack{display:flex;gap:2px;height:14px;margin:6px 0 12px}.stack>i{display:block;min-width:2px}.stack>i:first-child{border-radius:4px 0 0 4px}.stack>i:last-child{border-radius:0 4px 4px 0}.stack>i:only-child{border-radius:4px}
.blist{display:grid;grid-template-columns:auto 1fr auto auto;gap:6px 10px;align-items:center;font-size:13px}.blist .n{text-align:right;font-variant-numeric:tabular-nums}.blist .p{color:var(--muted);text-align:right;font-variant-numeric:tabular-nums;min-width:3.2em}
table{width:100%;border-collapse:collapse}th,td{padding:8px 8px;text-align:left;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:12px}tr:last-child td{border-bottom:0}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.tw{overflow-x:auto}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.mini{display:flex;gap:2px;height:8px;min-width:60px}.mini i{display:block;border-radius:2px}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--ink2);white-space:nowrap}
.tag{font-size:11px;border:1px solid var(--line);border-radius:5px;padding:1px 6px;color:var(--ink2);white-space:nowrap}
.chips{display:flex;flex-wrap:wrap;gap:6px;max-height:220px;overflow:auto;padding:2px}
.chip{display:inline-flex;align-items:center;gap:2px;background:var(--raised);border:1px solid var(--line);border-radius:99px;padding:2px 4px 2px 10px;font-size:12.5px;max-width:100%}
.chip span{overflow:hidden;text-overflow:ellipsis}.chip button{min-height:0;padding:0 7px;border:0;background:none;color:var(--muted);font-size:16px;line-height:1.3}.chip button:hover{color:var(--bad-ink)}
fieldset{border:1px solid var(--line);border-radius:var(--r);padding:12px 16px;margin:0;background:var(--surface);min-width:0}
legend{font-weight:600;padding:0 6px}
.chk{display:flex;gap:9px;align-items:flex-start;margin:9px 0}.chk input{margin-top:2px}.chk small{display:block;color:var(--muted)}
.fld{display:flex;flex-direction:column;gap:4px;flex:1 1 140px;font-size:12.5px;color:var(--ink2)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13px}.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
.meter{height:8px;border-radius:4px;background:var(--raised);overflow:hidden;margin:4px 0 10px}.meter i{display:block;height:100%;border-radius:4px;background:var(--accent)}
.status{display:flex;gap:10px;align-items:flex-start}.status .ic{font-size:18px;line-height:1.2}
details summary{cursor:pointer;color:var(--accent);font-size:12.5px;margin-top:8px}
#toast{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);max-width:calc(100% - 32px);background:var(--ink);color:var(--page);border-radius:10px;padding:10px 16px;box-shadow:0 6px 20px rgba(0,0,0,.25);display:none;z-index:9}
#toast.bad{background:var(--bad);color:#fff}
@media (max-width:560px){.hero .big{font-size:40px}.bar{padding:8px 12px}main{padding:10px 12px 72px}.blist{grid-template-columns:auto 1fr auto}.blist .p{display:none}}
@media (max-width:700px){#theme{order:2}.pills{order:3;width:100%;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}#pClock{display:none}html{scroll-padding-top:124px}}
@media (prefers-reduced-motion:no-preference){.meter i,.stack>i{transition:flex-grow .4s,width .4s}}
</style></head><body>
<header class=top><div class=bar>
<div class=brand><svg width=22 height=22 viewBox="0 0 24 24" aria-hidden=true><path fill=currentColor d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 13.6L7.4 12.2l1.4-1.4 2 2 4.4-4.4 1.4 1.4-5.8 5.8Z"/></svg>AdBlock</div>
<div class=pills><span id=pBlock class=pill><i class=dot></i><span>…</span></span><span id=pUp class=pill><i class=dot></i><span>…</span></span><span id=pClock class=pill><i class=dot></i><span>…</span></span><a id=pUpd class="pill is-info" href=#device hidden>update available</a></div>
<button id=theme class=ghost title="Theme: auto" aria-label="Switch theme">&#9680;</button></div>
<nav class=tabs aria-label=Sections><a href=#overview class=on>Overview</a><a href=#lists>Blocklist &amp; rules</a><a href=#clients>Clients</a><a href=#settings>Settings</a><a href=#device>Device</a></nav></header>
<main>
<div id=offline class="banner bad" hidden><p><b>Can't reach the device.</b> Retrying every few seconds; the page keeps the last values.</p></div>
<div id=setup class="banner warn" hidden><p><b>Set a dashboard password.</b> Find the one-time setup code on the serial console (<code>pio device monitor</code>), enter it with a new password (10+ characters). When the browser asks you to log in, use <code>admin</code> and the same setup code.</p>
<div class=row><input id=sCode placeholder="setup code" autocomplete=off aria-label="Setup code"><input id=sNew type=password placeholder="new password" autocomplete=new-password aria-label="New password"><button class=primary id=sSave>Set password</button></div></div>
<div id=plainBanner class="banner bad" hidden><p><b>Plain DNS in use.</b> Every encrypted upstream is down, so lookups currently go unencrypted (visible to your ISP). They return to DNS-over-TLS automatically.</p></div>
<div id=updBanner class="banner info" hidden><p id=updBannerText></p><a href=#device>Review &amp; install</a></div>

<section id=overview aria-labelledby=hOv><h2 id=hOv class=sr>Overview</h2>
<div class="card hero"><div><div class=big id=heroPct>–</div><div class=sub id=heroSub>of queries blocked</div></div>
<div class=ctl><div class=badge id=blkState></div><div class=seg role=group aria-label="Pause blocking"><button data-pause=300>Pause 5 min</button><button data-pause=3600>Pause 1 h</button><button data-pause=0>Pause</button><button id=resume class=primary hidden>Resume blocking</button></div></div></div>
<div class=tiles id=tiles></div>
<div class=grid style=margin-top:12px>
<div class=card><h3>Queries per minute</h3><div class=legend id=qLegend></div><div class=chart id=qChart tabindex=0 role=img aria-label="Queries per minute, allowed and blocked"><div id=tip></div></div>
<div class=hint>Live, from this browser's view since the page opened (last 30 min). Counters restart when the device reboots.</div></div>
<div class=card><h3>How queries were answered</h3><div class=hint>Since boot</div><div class=stack id=ansBar></div><div class=blist id=ansList></div></div></div>
<h2>Upstream DNS</h2><div class=card><div class=tw><table id=ups><thead><tr><th>Upstream</th><th>Transport</th><th>State</th><th class=n>OK</th><th class=n>Failed</th><th class=n>Latency</th><th>Trend</th></tr></thead><tbody></tbody></table></div>
<details id=upsMore hidden><summary></summary><div class=tw><table id=ups2><tbody></tbody></table></div></details>
<div class=hint style=margin-top:6px>Standby upstreams take over automatically when the active one fails.</div></div>
</section>

<section id=lists><h2>Blocklist &amp; rules</h2><div class=grid>
<div class=card><h3>Blocklist</h3><div id=blInfo></div>
<div class=row><label class=fld style=flex-basis:100%>List URL<input id=blUrl placeholder="https://.../blocklist.bin"></label></div>
<div class=row><label class=fld style="flex:0 1 120px">Daily update at<input id=blTime placeholder=02:00 inputmode=numeric></label><span class=hint style="flex:1 1 140px;align-self:flex-end">device time zone</span></div>
<div class=row><button id=blSave>Save</button><button id=blNow>Update now</button></div>
<div class=row><input type=file id=blFile accept=.bin aria-label="Blocklist file"><button id=blUpload>Upload list</button></div>
<div class=hint>Format v2 lists from <code>tools/build_blocklist.py</code>. A bad download or upload never replaces the current list.</div></div>
<div class=card><h3>Custom block</h3><form class=row data-add=block><input id=addBlock placeholder="ads.example.com" aria-label="Domain to block" autocapitalize=off spellcheck=false><button>Block</button></form><div class=chips id=ruleBlock></div>
<div class=hint>Blocks the domain and its subdomains.</div></div>
<div class=card><h3>Allowlist</h3><form class=row data-add=allow><input id=addAllow placeholder="cdn.example.com" aria-label="Domain to allow" autocapitalize=off spellcheck=false><button>Allow</button></form><div class=chips id=ruleAllow></div>
<div class=hint>Always resolves, even if the blocklist has it.</div></div></div></section>

<section id=clients><h2>Clients</h2><div class=card><div class=row style=margin-top:0><input id=cFilter type=search placeholder="Filter by IP or MAC" aria-label="Filter clients" style="flex:0 1 260px"><span class=legend style=margin:0><span class=key><i class=sw style=background:var(--s-allowed)></i>allowed</span><span class=key><i class=sw style=background:var(--s-blocked)></i>blocked</span></span></div>
<div class=tw><table id=clientT><thead><tr><th>Device</th><th>MAC</th><th class=n>Allowed</th><th class=n>Blocked</th><th style=width:22%>Share</th><th></th></tr></thead><tbody></tbody></table></div></div></section>

<section id=settings><h2>Settings</h2><form id=cfg class=grid>
<fieldset><legend>Upstream</legend>
<div class=row><label class=fld>Primary<select name=up_pri><option>cloudflare<option>quad9<option>custom</select></label><label class=fld>Secondary<select name=up_sec><option>quad9<option>cloudflare<option>custom<option>none</select></label></div>
<label class=chk><input type=checkbox name=up_doh><span>DoH fallback<small>Use DNS-over-HTTPS if port 853 is blocked</small></span></label>
<label class=chk><input type=checkbox name=up_plain><span>Plain DNS as last resort<small>Only while every encrypted upstream is down</small></span></label>
<div class=row><label class=fld>Custom DoT IP<input name=up_cip placeholder="IP"></label><label class=fld>Second IP<input name=up_cip2 placeholder="IP 2"></label></div>
<div class=row><label class=fld>TLS name<input name=up_cname placeholder="dns.example.com" autocapitalize=off></label></div>
<label class=chk><input type=checkbox name=up_cdoh><span>Custom provider also serves DoH</span></label></fieldset>
<fieldset><legend>Privacy &amp; blocking</legend>
<label class=chk><input type=checkbox name=pad><span>Pad encrypted queries<small>RFC 8467, hides query length</small></span></label>
<label class=chk><input type=checkbox name=ad><span>Pass DNSSEC "validated" (AD) flag</span></label>
<label class=chk><input type=checkbox name=ff_canary><span>Stop Firefox bypassing via its own DoH</span></label>
<label class=chk><input type=checkbox name=icloud><span>Disable iCloud Private Relay on this network</span></label>
<label class=chk><input type=checkbox name=priv_rev><span>Answer private reverse lookups locally</span></label>
<div class=row><label class=fld style="flex:0 1 130px">Blocked answer TTL (s)<input name=blk_ttl inputmode=numeric></label><label class=fld>Time zone<input name=tz placeholder=UTC0 title="POSIX TZ string: UTC0, or e.g. &lt;+03&gt;-3 for UTC+3 and &lt;-05&gt;5 for UTC-5 (the sign is inverted)"></label><label class=fld style="flex:0 1 110px">Log level<select name=log><option value=0>error<option value=1>warn<option value=2>info<option value=3>debug</select></label></div>
<div class=hint>Time zone is a POSIX TZ string: <code>UTC0</code>, <code>&lt;+03&gt;-3</code> for UTC+3, <code>&lt;-05&gt;5</code> for UTC−5 (the sign is inverted).</div></fieldset>
<div class="row" style="grid-column:1/-1"><button class=primary>Save settings</button><span class=hint>Upstream changes restart the device.</span></div></form></section>

<section id=device><h2>Device</h2><div class=grid>
<div class=card><h3>Firmware</h3><div class=status id=upd><span class=ic aria-hidden=true>&#8635;</span><div><b>Checking for updates…</b></div></div>
<div class=row><button id=upFlash class=primary hidden>Download &amp; install</button><button id=upCheck class=ghost hidden>Check again</button></div>
<details><summary>Install a firmware file manually</summary><div class=row><input type=file id=fwFile accept=.bin aria-label="Firmware file"><button id=fwUpload>Flash firmware</button></div>
<div class=hint>The device reboots and rolls back if the new firmware is unhealthy.</div></details></div>
<div class=card><h3>Health</h3><div id=dev></div></div>
<div class=card><h3>Maintenance</h3><div class=row><button id=flush>Flush DNS cache</button><button id=reboot>Reboot</button><button id=forget class=danger>Forget Wi-Fi</button></div>
<h3 style=margin-top:14px>Change password</h3><div class=row><input id=pCur type=password placeholder=current autocomplete=current-password aria-label="Current password"><input id=pNew type=password placeholder="new (10+ characters)" autocomplete=new-password aria-label="New password"><button id=pSave>Change</button></div></div>
</div></section>
</main><div id=toast role=status aria-live=polite></div>
<script>
const $=id=>document.getElementById(id),NS='http://www.w3.org/2000/svg';
function toast(t,bad){const e=$('toast');e.textContent=t;e.className=bad?'bad':'';e.style.display='block';clearTimeout(e._t);e._t=setTimeout(()=>e.style.display='none',4500)}
async function api(path,data,body){
 const opt={method:'POST',credentials:'same-origin',headers:{'X-Requested-With':'adblock'}};
 if(body){opt.body=body}else{opt.headers['Content-Type']='application/x-www-form-urlencoded';opt.body=new URLSearchParams(data||{})}
 try{const r=await fetch(path,opt);const t=await r.text();toast(t||r.statusText,!r.ok);if(r.ok)load();return r.ok}catch(e){toast('request failed: '+e.message,true);return false}}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined&&text!==null)e.textContent=text;if(cls)e.className=cls;return e}
function sv(tag,a,p){const e=document.createElementNS(NS,tag);for(const k in a)e.setAttribute(k,a[k]);if(p)p.append(e);return e}
function fmt(n){return Number(n).toLocaleString()}
function compact(n){n=Number(n);return n>=1e6?(n/1e6).toFixed(n>=1e7?0:1)+'M':n>=1e4?(n/1e3).toFixed(n>=1e5?0:1)+'K':fmt(n)}
function mb(b){return (b/1048576).toFixed(b>=104857600?0:1)+' MB'}
function pct(a,b){return b?Math.round(100*a/b):0}
function setPill(id,text,state){const p=$(id);p.className='pill is-'+state;p.lastChild.textContent=text}
function key(color,label,val,line){const k=el('span',undefined,'key');k.append(el('i',undefined,line?'ln':'sw'));k.firstChild.style.background=color;k.append(label);if(val!==undefined){k.append(' ',el('b',val))}return k}
function cssVar(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()}

// Theme: auto (OS) / light / dark, remembered in this browser only.
const themes=['auto','light','dark'];let theme='auto';try{theme=localStorage.getItem('ab.theme')||'auto'}catch(e){}
function applyTheme(){if(theme==='auto')delete document.documentElement.dataset.theme;else document.documentElement.dataset.theme=theme;$('theme').title='Theme: '+theme}
$('theme').onclick=()=>{theme=themes[(themes.indexOf(theme)+1)%3];try{localStorage.setItem('ab.theme',theme)}catch(e){}applyTheme();if(last)render(last)};applyTheme();

// Section nav highlights the section in view.
const navLinks=[...document.querySelectorAll('nav.tabs a')];
const sections=[...document.querySelectorAll('main section')];let navT=0;
function navSync(){navT=0;let cur=sections[0];for(const s of sections)if(s.getBoundingClientRect().top<=130)cur=s;
 if(innerHeight+scrollY>=document.documentElement.scrollHeight-4)cur=sections[sections.length-1];navLinks.forEach(a=>a.classList.toggle('on',a.hash==='#'+cur.id))}
addEventListener('scroll',()=>{if(!navT)navT=requestAnimationFrame(navSync)},{passive:true});

// History of counter samples, kept in this browser (no extra load on the device).
const WINDOW=30*60*1000;let hist=[],lat={};
try{const h=JSON.parse(sessionStorage.getItem('ab.hist')||'{}');if(Array.isArray(h.s))hist=h.s;if(h.l)lat=h.l}catch(e){}
function record(s){const now=Date.now(),d=s.dns,p=hist[hist.length-1];
 if(p&&(d.queries<p.q||d.blocked<p.b))hist=[];  // counters restarted: the device rebooted
 hist.push({t:now,q:d.queries,b:d.blocked});while(hist.length&&now-hist[0].t>WINDOW)hist.shift();
 for(const u of s.upstreams){if(!u.ok&&!u.failed)continue;const a=lat[u.name]||(lat[u.name]=[]);a.push(u.latencyMs);if(a.length>40)a.shift()}
 try{sessionStorage.setItem('ab.hist',JSON.stringify({s:hist,l:lat}))}catch(e){}}
// Per-minute rates over a ~20 s sliding window (smooths the 4 s polls).
function rates(){const out=[];for(let i=1;i<hist.length;i++){const j=Math.max(0,i-5),a=hist[j],z=hist[i],dt=(z.t-a.t)/60000;if(dt<=0)continue;
 const q=(z.q-a.q)/dt,b=(z.b-a.b)/dt;out.push({t:z.t,a:Math.max(0,q-b),b:Math.max(0,b)})}return out}
// Round time ticks (every 5 s, 1 min, 15 min, ...) aligned to local clock time, at most `max` of them.
function timeTicks(t0,t1,max){const steps=[1,2,5,10,15,30,60,120,300,600,900,1800].map(s=>s*1000),off=-new Date(t0).getTimezoneOffset()*60000;let step=steps[steps.length-1];for(const s of steps)if((t1-t0)/s<=max){step=s;break}const ticks=[];for(let t=Math.ceil((t0+off)/step)*step-off;t<=t1;t+=step)ticks.push(t);return {step,ticks}}
function niceMax(v){if(v<=0)return 4;const p=Math.pow(10,Math.floor(Math.log10(v))),f=v/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p}
const p2=n=>String(n).padStart(2,'0');
function hhmm(t,sec){const d=new Date(t);return p2(d.getHours())+':'+p2(d.getMinutes())+(sec?':'+p2(d.getSeconds()):'')}

function spark(svg,vals,color){svg.replaceChildren();if(vals.length<2)return;const w=100,h=28,mx=Math.max(...vals,1e-9),mn=Math.min(...vals,0);
 svg.setAttribute('viewBox','0 0 '+w+' '+h);svg.setAttribute('preserveAspectRatio','none');
 const pts=vals.map((v,i)=>[i*w/(vals.length-1),h-2-(h-4)*(v-mn)/((mx-mn)||1)]);
 sv('polyline',{points:pts.map(p=>p.join(',')).join(' '),fill:'none',stroke:'var(--axis)','stroke-width':1.5,'vector-effect':'non-scaling-stroke','stroke-linejoin':'round'},svg);
 const l=pts[pts.length-1];sv('circle',{cx:l[0],cy:l[1],r:2.5,fill:color},svg)}

let chartPts=[],hover=-1;
function drawChart(){const box=$('qChart'),tip=$('tip');[...box.children].forEach(c=>{if(c!==tip)c.remove()});
 const pts=chartPts;if(pts.length<2){box.prepend(el('div','Collecting data… the chart fills in while this page stays open.','empty'));tip.style.display='none';return}
 const W=Math.max(260,box.clientWidth),H=190,L=34,R=8,T=8,B=22,iw=W-L-R,ih=H-T-B;
 const t0=pts[0].t,t1=pts[pts.length-1].t,span=Math.max(t1-t0,1),ymax=niceMax(Math.max(...pts.map(p=>Math.max(p.a,p.b))));
 const x=t=>L+iw*(t-t0)/span,y=v=>T+ih-ih*v/ymax;
 const svg=sv('svg',{viewBox:'0 0 '+W+' '+H,height:H});
 for(let i=0;i<=4;i++){const v=ymax*i/4,yy=y(v);sv('line',{x1:L,x2:W-R,y1:yy,y2:yy,stroke:i?'var(--line)':'var(--axis)','stroke-width':1},svg);
  const tx=sv('text',{x:L-6,y:yy+4,'text-anchor':'end','font-size':11,fill:'var(--muted)'},svg);tx.textContent=compact(Math.round(v*10)/10)}
 const tk=timeTicks(t0,t1,Math.min(6,Math.max(2,Math.floor(iw/80))));for(const t of tk.ticks){const xx=x(t),tx=sv('text',{x:xx,y:H-5,'text-anchor':xx<L+30?'start':xx>W-R-30?'end':'middle','font-size':11,fill:'var(--muted)'},svg);tx.textContent=hhmm(t,tk.step<60000)}
 const path=k=>pts.map((p,i)=>(i?'L':'M')+x(p.t).toFixed(1)+' '+y(p[k]).toFixed(1)).join('');
 sv('path',{d:path('a')+'L'+x(t1)+' '+y(0)+'L'+x(t0)+' '+y(0)+'Z',fill:'var(--s-allowed)','fill-opacity':.1},svg);
 for(const [k,c] of [['a','var(--s-allowed)'],['b','var(--s-blocked)']]){sv('path',{d:path(k),fill:'none',stroke:c,'stroke-width':2,'stroke-linejoin':'round','stroke-linecap':'round'},svg);
  const p=pts[pts.length-1];sv('circle',{cx:x(p.t),cy:y(p[k]),r:4,fill:c,stroke:'var(--surface)','stroke-width':2},svg)}
 const g=sv('g',{},svg),hit=sv('rect',{x:L,y:T,width:iw,height:ih,fill:'transparent'},svg);
 function show(i){g.replaceChildren();if(i<0||i>=pts.length){tip.style.display='none';return}const p=pts[i],xx=x(p.t);
  sv('line',{x1:xx,x2:xx,y1:T,y2:T+ih,stroke:'var(--axis)','stroke-width':1},g);
  for(const [k,c] of [['a','var(--s-allowed)'],['b','var(--s-blocked)']])sv('circle',{cx:xx,cy:y(p[k]),r:4,fill:c,stroke:'var(--surface)','stroke-width':2},g);
  tip.replaceChildren(el('div',hhmm(p.t,1),'t'),key('var(--s-allowed)','allowed',Math.round(p.a)+'/min'),el('br'),key('var(--s-blocked)','blocked',Math.round(p.b)+'/min'));
  tip.style.display='block';const sx=box.clientWidth/W,left=xx*sx;tip.style.top='4px';tip.style.left=(left>box.clientWidth/2?left-tip.offsetWidth-12:left+12)+'px'}
 function at(ev){const r=svg.getBoundingClientRect(),px=(ev.clientX-r.left)*W/r.width;let best=0;for(let i=1;i<pts.length;i++)if(Math.abs(x(pts[i].t)-px)<Math.abs(x(pts[best].t)-px))best=i;return best}
 hit.onpointermove=ev=>{hover=at(ev);show(hover)};hit.onpointerdown=hit.onpointermove;hit.onpointerleave=()=>{hover=-1;show(-1)};
 box._show=show;box.prepend(svg);if(hover>=0)show(Math.min(hover,pts.length-1))}
$('qChart').onkeydown=e=>{if(!chartPts.length)return;if(e.key==='ArrowLeft')hover=Math.max(0,(hover<0?chartPts.length:hover)-1);else if(e.key==='ArrowRight')hover=Math.min(chartPts.length-1,hover+1);else if(e.key==='Escape')hover=-1;else return;e.preventDefault();$('qChart')._show&&$('qChart')._show(hover)};
$('qChart').onblur=()=>{hover=-1;$('qChart')._show&&$('qChart')._show(-1)};
let rz;window.addEventListener('resize',()=>{clearTimeout(rz);rz=setTimeout(drawChart,150)});

function tile(label,value,sub,trend,color){const c=el('div',undefined,'card tile');c.append(el('div',label,'l'),el('div',value,'v'));if(sub)c.append(el('div',sub,'s'));
 if(trend){const s=sv('svg',{'aria-hidden':'true'});spark(s,trend,color);c.append(s)}return c}
function transport(n,enc){return /doh/.test(n)?'DoH':/udp/.test(n)||!enc?'UDP (plain)':'DoT'}
function stateBadge(st){const m={up:['is-good','up'],down:['is-bad','down'],unknown:['','standby']}[st]||['',st];const b=el('span',undefined,'badge '+m[0]);b.append(el('i',undefined,'dot'),m[1]);return b}

let cfgLoaded=false,last=null,updChecked=false;
async function load(){let s;
 try{const r=await fetch('/api/stats',{cache:'no-store'});s=await r.json()}catch(e){$('offline').hidden=false;setPill('pUp','offline','bad');return}
 $('offline').hidden=true;record(s);last=s;render(s);
 if(!updChecked){updChecked=true;checkUpdate()}
 if(!cfgLoaded){try{const c=await (await fetch('/api/config')).json();for(const [k,v] of Object.entries(c)){const i=$('cfg').elements[k];if(!i)continue;if(i.type==='checkbox')i.checked=v;else i.value=v}cfgLoaded=true}catch(e){}}}
function render(s){const d=s.dns,bl=s.blocklist;
 document.title=(s.blocking?'':'(paused) ')+'AdBlock · '+s.hostname;
 setPill('pBlock',s.blocking?'blocking on':(s.resumeIn?'paused · '+Math.ceil(s.resumeIn/60)+' min left':'paused'),s.blocking?'good':'warn');
 const enc=s.upstreams.find(u=>u.encrypted&&u.state==='up');
 setPill('pUp',s.plainFallback?'plain DNS':(enc?'encrypted · '+enc.name:'encrypted DNS'),s.plainFallback?'bad':(enc?'good':'warn'));
 setPill('pClock',s.timeSynced?s.now:'clock not synced',s.timeSynced?'good':'warn');
 $('setup').hidden=!s.setupRequired;$('plainBanner').hidden=!s.plainFallback;
 // Hero + blocking control
 $('heroPct').textContent=pct(d.blocked,d.queries)+'%';
 $('heroSub').textContent=fmt(d.blocked)+' of '+fmt(d.queries)+' queries blocked since boot ('+s.uptime+')';
 const bs=$('blkState');bs.className='badge is-'+(s.blocking?'good':'warn');bs.replaceChildren(el('i',undefined,'dot'),s.blocking?'Blocking is on':(s.resumeIn?'Paused, resumes in '+Math.ceil(s.resumeIn/60)+' min':'Paused until you resume'));
 $('resume').hidden=s.blocking;
 // Tiles
 const r=rates();chartPts=r;const qr=r.slice(-24).map(p=>p.a+p.b),br=r.slice(-24).map(p=>p.b);
 const lastRate=r.length?Math.round(r[r.length-1].a+r[r.length-1].b):null;
 $('tiles').replaceChildren(
  tile('Queries',compact(d.queries),lastRate===null?'since boot':lastRate+' per min now',qr,'var(--s-allowed)'),
  tile('Blocked',compact(d.blocked),pct(d.blocked,d.queries)+'% of queries',br,'var(--s-blocked)'),
  tile('Cache hit rate',pct(d.cacheHits,d.cacheHits+d.forwarded)+'%',fmt(d.cacheEntries)+' answers cached'),
  tile('Failed lookups',compact(d.servfail),d.servfail?pct(d.servfail,d.queries)+'% answered SERVFAIL':'none since boot'),
  tile('Blocklist',compact(bl.entries),'domains '+(bl.inMemory?'in PSRAM':'from flash')),
  tile('Clients',fmt(s.clients.length),s.clients.filter(c=>c.banned).length+' banned'));
 // Chart legend + chart
 const lp=r[r.length-1];$('qLegend').replaceChildren(key('var(--s-allowed)','allowed',lp?Math.round(lp.a)+'/min':'–',1),key('var(--s-blocked)','blocked',lp?Math.round(lp.b)+'/min':'–',1));drawChart();
 // Answer breakdown (part of whole). Forwarded lookups that later failed also count as SERVFAIL.
 const parts=[['Blocked',d.blocked,'--s-blocked'],['Cache',d.cacheHits,'--s-cache'],['Forwarded',d.forwarded,'--s-fwd'],['Local',d.local,'--s-local']];
 parts.push(['Other (errors, dropped)',Math.max(0,d.queries-parts.reduce((a,p)=>a+p[1],0)),'--s-other']);
 const tot=Math.max(1,parts.reduce((a,p)=>a+p[1],0));
 $('ansBar').replaceChildren(...parts.filter(p=>p[1]>0).map(p=>{const i=el('i');i.style.flexGrow=p[1];i.style.background='var('+p[2]+')';i.title=p[0]+': '+fmt(p[1])+' ('+pct(p[1],tot)+'%)';return i}));
 if(!d.queries){const i=el('i');i.style.flexGrow=1;i.style.background='var(--raised)';$('ansBar').replaceChildren(i)}
 $('ansList').replaceChildren(...parts.flatMap(p=>{const sw=el('i',undefined,'sw');sw.style.background='var('+p[2]+')';return [sw,el('span',p[0]),el('span',fmt(p[1]),'n'),el('span',pct(p[1],tot)+'%','p')]}));
 // Upstreams: active ones in the table, idle standby ones folded away
 const act=s.upstreams.filter(u=>u.state!=='unknown'||u.ok||u.failed),idle=s.upstreams.filter(u=>!act.includes(u));
 const urow=u=>{const tr=el('tr'),td=el('td');td.append(stateBadge(u.state));const tdS=el('td'),sp=sv('svg',{width:80,height:22,'aria-hidden':'true'});spark(sp,lat[u.name]||[],'var(--s-allowed)');tdS.append(sp);
  tr.append(el('td',u.name,'mono'),el('td',transport(u.name,u.encrypted)),td,el('td',fmt(u.ok),'n'),el('td',fmt(u.failed),'n'),el('td',u.ok?u.latencyMs+' ms':'–','n'),tdS);return tr};
 $('ups').tBodies[0].replaceChildren(...act.map(urow));if(!act.length){const tr=el('tr'),td=el('td','No lookups forwarded yet','hint');td.colSpan=7;tr.append(td);$('ups').tBodies[0].append(tr)}
 $('upsMore').hidden=!idle.length;$('upsMore').firstChild.textContent=idle.length+' standby upstream'+(idle.length>1?'s':'');
 $('ups2').tBodies[0].replaceChildren(...idle.map(u=>{const tr=el('tr'),td=el('td');td.append(stateBadge(u.state));tr.append(el('td',u.name,'mono'),el('td',transport(u.name,u.encrypted)),td);return tr}));
 // Blocklist
 const st=el('div',undefined,'badge is-'+(bl.lastOk?'good':'warn'));st.append(el('i',undefined,'dot'),'Last update '+bl.lastAttempt+': '+bl.lastResult);
 const dl=el('dl',undefined,'kv');for(const [k,v] of [['Domains',fmt(bl.entries)+(bl.inMemory?' (in PSRAM)':' (from flash)')],['Built',bl.built],['Next update','daily at '+bl.time]])dl.append(el('dt',k),el('dd',v));
 $('blInfo').replaceChildren(dl,el('div',undefined,'row'));$('blInfo').lastChild.append(st);
 if(document.activeElement!==$('blUrl'))$('blUrl').value=bl.url;if(document.activeElement!==$('blTime'))$('blTime').value=bl.time;
 for(const [list,id] of [['block','ruleBlock'],['allow','ruleAllow']]){const items=s.rules[list];
  $(id).replaceChildren(...(items.length?items.map(dm=>{const c=el('span',undefined,'chip'),b=el('button','×');b.title='Remove '+dm;b.setAttribute('aria-label','Remove '+dm);b.onclick=()=>api('/api/rules/remove',{list,d:dm});c.append(el('span',dm,'mono'),b);return c}):[el('span','No rules yet','hint')]))}
 renderClients();
 // Device health
 const q=s.rssi>=-55?'excellent':s.rssi>=-67?'good':s.rssi>=-75?'fair':'weak',qp=Math.max(5,Math.min(100,(s.rssi+95)*100/60));
 const PSRAM=8388608,used=Math.max(0,PSRAM-s.psram);
 const dv=el('dl',undefined,'kv');for(const [k,v] of [['Address',s.hostname+'.local · '+s.ip],['Firmware','v'+s.version],['Uptime',s.uptime],['Temperature',s.temp+' °C'],['Free heap',fmt(s.heap)+' B (lowest '+fmt(s.heapMin)+' B, largest block '+fmt(s.heapBlock)+' B)']])dv.append(el('dt',k),el('dd',v));
 const m=(label,val,w,color)=>{const f=document.createDocumentFragment(),bar=el('div',undefined,'meter'),i=el('i');i.style.width=w+'%';if(color)i.style.background=color;bar.append(i);f.append(el('div',label,'hint'),bar);return f};
 $('dev').replaceChildren(m('Wi-Fi signal: '+q+' ('+s.rssi+' dBm)',null,qp,qp<35?'var(--warn)':null),m('PSRAM: '+mb(s.psram)+' free of 8 MB',null,100*used/PSRAM),dv)}

// Fixed order (by IP): the table redraws every poll, and sorting by activity moved rows
// under the cursor, so a Ban click could land on another client (found on hardware).
const ipNum=ip=>ip.split('.').reduce((n,o)=>n*256+(+o||0),0);
function renderClients(){if(!last)return;const f=$('cFilter').value.trim().toLowerCase(),list=last.clients.slice().sort((a,b)=>ipNum(a.ip)-ipNum(b.ip));
 const max=Math.max(1,...list.map(c=>c.blocked+c.allowed)),shown=list.filter(c=>!f||c.ip.includes(f)||c.mac.includes(f));
 const tb=$('clientT').tBodies[0];tb.replaceChildren(...shown.map(c=>{const tr=el('tr'),b=el('button',c.banned?'Unban':'Ban',c.banned?'':'danger');b.onclick=()=>{if(c.banned||confirm('Ban '+c.ip+'? It gets no DNS answers until you unban it.'))api('/api/clients/ban',{ip:c.ip})};
  const ip=el('td',undefined,'mono');ip.append(c.ip);if(c.banned){ip.append(' ',el('span','banned','tag'))}
  const sh=el('td'),bar=el('div',undefined,'mini'),tot=c.blocked+c.allowed;bar.style.width=Math.max(6,100*tot/max)+'%';bar.title=pct(c.blocked,tot)+'% blocked';
  for(const [n,v] of [[c.allowed,'--s-allowed'],[c.blocked,'--s-blocked']])if(n){const i=el('i');i.style.flexGrow=n;i.style.background='var('+v+')';bar.append(i)}sh.append(bar);
  const ac=el('td');ac.append(b);tr.append(ip,el('td',c.mac,'mono ink2'),el('td',fmt(c.allowed),'n'),el('td',fmt(c.blocked),'n'),sh,ac);return tr}));
 if(!shown.length){const tr=el('tr'),td=el('td',list.length?'No client matches the filter':'No clients yet','hint');td.colSpan=6;tr.append(td);tb.append(tr)}}
$('cFilter').oninput=renderClients;

document.querySelectorAll('[data-pause]').forEach(b=>b.onclick=()=>api('/api/blocking/pause',{s:b.dataset.pause}));
$('resume').onclick=()=>api('/api/blocking/resume');
document.querySelectorAll('form[data-add]').forEach(f=>f.onsubmit=async e=>{e.preventDefault();const list=f.dataset.add,i=f.querySelector('input');if(i.value.trim()&&await api('/api/rules/add',{list,d:i.value.trim()}))i.value=''});
$('blSave').onclick=()=>api('/api/blocklist/settings',{u:$('blUrl').value.trim(),t:$('blTime').value.trim()});
$('blNow').onclick=()=>api('/api/blocklist/update');
function upload(path,input){const f=$(input).files[0];if(!f)return toast('choose a file first',true);const fd=new FormData();fd.append('f',f);toast('uploading '+(f.size/1048576).toFixed(2)+' MB...');api(path,null,fd)}
$('blUpload').onclick=()=>upload('/api/blocklist/upload','blFile');

// Updates: checked automatically when the page loads. The browser fetches update.json
// and the firmware from the update site (GitHub Pages: release downloads send no CORS
// headers), keeps it in memory and sends it through the normal upload, so the same
// health check and rollback apply.
let upd=null;
function verCmp(a,b){const p=v=>String(v).replace(/^v/,'').split(/[-+]/)[0].split('.').map(n=>parseInt(n,10)||0);const x=p(a),y=p(b);for(let i=0;i<3;i++){const d=(x[i]||0)-(y[i]||0);if(d)return d}return 0}
function updState(icon,title,detail,link){const box=$('upd'),txt=el('div');txt.append(el('b',title));if(detail)txt.append(el('div',detail,'hint'));
 if(link&&/^https:\/\//.test(link)){const a=el('a','Release notes');a.href=link;a.target='_blank';a.rel='noopener';txt.append(a)}
 box.replaceChildren(el('span',icon,'ic'),txt);box.firstChild.setAttribute('aria-hidden','true')}
function updNotice(text){$('pUpd').hidden=!text;$('updBanner').hidden=!text;if(text){$('pUpd').textContent=text;$('updBannerText').textContent='Firmware '+text.replace('update ','')+'. Settings are kept.'}}
async function checkUpdate(){upd=null;$('upFlash').hidden=true;$('upCheck').hidden=true;updState('↻','Checking for updates…');
 try{const s=last;const r=await fetch(s.updateUrl+'update.json',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const j=await r.json();
 if(!j.version||!j.firmware||!(j.size>0))throw Error('bad update.json');
 if(verCmp(j.version,s.version)<=0){updState('✓','Up to date','v'+s.version+' is the latest release.',j.release);updNotice('');$('upCheck').hidden=false;return}
 // Never offer what this dashboard can't safely install: an update.json format it doesn't
 // know (schema), or a release that needs a USB flash from this version (minUpdateFrom).
 const manual=(j.schema||1)>1?'This dashboard is too old to install it; use the web installer.':(j.minUpdateFrom&&verCmp(s.version,j.minUpdateFrom)<0)?'It needs a USB install from v'+s.version+' (web installer).':'';
 if(manual){updState('!','v'+j.version+' available',manual,j.release);updNotice('update v'+j.version+' available');return}
 upd=Object.assign({},j,{base:s.updateUrl});updState('↑','v'+j.version+' available','Running v'+s.version+' · download '+(j.size/1048576).toFixed(2)+' MB. Rolls back automatically if unhealthy.',j.release);
 updNotice('update v'+j.version+' available');$('upFlash').hidden=false}
 catch(e){updState('!','Couldn\'t check for updates',e.message+' (needs internet access from this browser)');$('upCheck').hidden=false}}
$('upCheck').onclick=checkUpdate;
// After an update: poll until the device is back and report what it runs. A fresh
// boot shows as an unreachable device or an uptime under a minute.
async function waitForVersion(v){const t0=Date.now();let restarted=false;
 while(Date.now()-t0<180000){await new Promise(r=>setTimeout(r,3000));
  try{const s=await (await fetch('/api/stats',{cache:'no-store'})).json();
   if(s.version===v){updState('✓','Updated','Now running v'+v+'.');updNotice('');load();return}
   if(restarted||/^0d 0h 0m/.test(s.uptime)){updState('!','Update did not stick','The device restarted on v'+s.version+': v'+v+' was rolled back.');load();return}}
  catch(e){restarted=true;updState('↻','v'+v+' installed, restarting…')}}
 updState('!','The device is not back yet','Reload this page in a minute.')}
$('upFlash').onclick=async()=>{if(!upd)return;
 if(!confirm('Download v'+upd.version+' ('+(upd.size/1048576).toFixed(2)+' MB) and flash it? The device reboots and rolls back if the new firmware is unhealthy.'))return;
 const btn=$('upFlash');btn.disabled=true;
 try{updState('↓','Downloading v'+upd.version+'…');const r=await fetch(new URL(upd.firmware,upd.base),{cache:'no-store'});if(!r.ok)throw Error('download HTTP '+r.status);
 const buf=await r.arrayBuffer();if(buf.byteLength!==upd.size)throw Error('downloaded '+buf.byteLength+' bytes, expected '+upd.size);
 if(new Uint8Array(buf)[0]!==0xE9)throw Error('not an ESP32 firmware image');
 const fd=new FormData();fd.append('f',new Blob([buf],{type:'application/octet-stream'}),'firmware-esp32s3-v'+upd.version+'.bin');
 updState('↑','Uploading v'+upd.version+' to the device…','Keep this page open.');if(await api('/api/firmware',null,fd)){updState('↻','v'+upd.version+' installed, rebooting…');btn.hidden=true;waitForVersion(upd.version)}else checkUpdate()}
 catch(e){toast('update failed: '+e.message,true);checkUpdate()}finally{btn.disabled=false}};
$('fwUpload').onclick=()=>{if(confirm('Flash this firmware? The device reboots and rolls back if the new firmware is unhealthy.'))upload('/api/firmware','fwFile')};
$('flush').onclick=()=>api('/api/cache/flush');
$('reboot').onclick=()=>{if(confirm('Reboot the device?'))api('/api/reboot')};
$('forget').onclick=()=>{if(confirm('Forget Wi-Fi and reboot into the setup access point?'))api('/api/wifi/forget')};
$('cfg').onsubmit=e=>{e.preventDefault();const data={};for(const i of $('cfg').elements){if(!i.name)continue;data[i.name]=i.type==='checkbox'?(i.checked?'1':'0'):i.value}api('/api/config',data)};
$('sSave').onclick=()=>api('/api/password',{current:$('sCode').value.trim(),next:$('sNew').value});
$('pSave').onclick=()=>api('/api/password',{current:$('pCur').value,next:$('pNew').value});
load();setInterval(load,4000);
</script></body></html>)HTML";

}  // namespace web
