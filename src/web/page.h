#pragma once
// Dashboard single page (served from flash). Security rules for this file:
//  - never put server data into innerHTML: build nodes, set textContent/value
//  - every change is a POST through api(), which adds X-Requested-With: adblock
// Kept in its own header so the Arduino IDE preprocessor doesn't choke on it.

#include <pgmspace.h>

namespace web {

const char kPage[] PROGMEM = R"HTML(<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>AdBlock</title><style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
header{background:var(--card);padding:12px 16px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px;align-items:center}
h1{margin:0 12px 0 0;font-size:18px}h1 b{color:var(--ok)}h2{font-size:13px;color:var(--dim);letter-spacing:.06em;margin:22px 0 8px}
.wrap{padding:12px 16px;max-width:1100px;margin:auto}.pill{border:1px solid var(--line);border-radius:99px;padding:2px 10px;font-size:12px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.dim{color:var(--dim)}
.banner{border:1px solid var(--bad);background:#2d1214;border-radius:8px;padding:10px 14px;margin:10px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px}.card .v{font-size:21px;font-weight:600}.card .l{color:var(--dim);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}th{color:var(--dim);font-weight:500}
input,select,button{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font:inherit}
button{background:#21262d;cursor:pointer}button:hover{background:var(--line)}button.primary{background:#238636;border-color:#2ea043}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:6px 0}.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
label{display:flex;gap:6px;align-items:center}fieldset{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:0}legend{color:var(--dim)}
#toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px;display:none}
.scroll{max-height:260px;overflow:auto}
</style></head><body>
<header><h1>&#128737; <b>AdBlock</b></h1><span id=ver class="pill dim"></span><span id=pBlock class=pill></span><span id=pUp class=pill></span><span id=pClock class=pill></span></header>
<div class=wrap>
<div id=setup class=banner hidden><b>Set a dashboard password.</b> Find the one-time setup code on the serial console (<code>pio device monitor</code>). Enter it below with a new password (10+ characters); when the browser asks you to log in, use <code>admin</code> and the same setup code.
<div class=row><input id=sCode placeholder="setup code" autocomplete=off><input id=sNew type=password placeholder="new password" autocomplete=new-password><button class=primary id=sSave>Set password</button></div></div>
<div id=plainBanner class=banner hidden><b>Plain DNS in use.</b> Every encrypted upstream is down, so lookups currently go unencrypted (visible to your ISP). They return to DNS-over-TLS automatically.</div>
<div class=cards id=cards></div>
<div class=row style=margin-top:12px><b>Blocking</b> <button data-pause=300>Pause 5 min</button><button data-pause=3600>Pause 1 h</button><button data-pause=0>Pause</button><button id=resume>Resume</button></div>
<div class=grid2><div><h2>UPSTREAM DNS</h2><table id=ups><thead><tr><th>Upstream</th><th>Type</th><th>State</th><th>OK</th><th>Fail</th><th>Latency</th></tr></thead><tbody></tbody></table></div>
<div><h2>BLOCKLIST</h2><div class=card><div id=blInfo></div>
<div class=row><input id=blUrl size=38 placeholder="https://.../blocklist.bin"> daily at <input id=blTime size=5 placeholder=02:00> <button id=blSave>Save</button><button id=blNow>Update now</button></div>
<div class=row><input type=file id=blFile accept=.bin><button id=blUpload>Upload list</button></div>
<div class=dim>Format v2 lists from <code>tools/build_blocklist.py</code>. A bad download or upload never replaces the current list.</div></div></div></div>
<div class=grid2><div><h2>CUSTOM BLOCK</h2><div class=row><input id=addBlock placeholder="ads.example.com"><button data-add=block>Block</button></div><div class=scroll><table id=ruleBlock><tbody></tbody></table></div></div>
<div><h2>ALLOWLIST</h2><div class=row><input id=addAllow placeholder="cdn.example.com"><button data-add=allow>Allow</button></div><div class=scroll><table id=ruleAllow><tbody></tbody></table></div></div></div>
<h2>CLIENTS</h2><div class=scroll><table id=clients><thead><tr><th>IP</th><th>MAC</th><th>Blocked</th><th>Allowed</th><th></th></tr></thead><tbody></tbody></table></div>
<h2>SETTINGS</h2><form id=cfg class=grid2>
<fieldset><legend>Upstream</legend>
<div class=row>Primary <select name=up_pri><option>cloudflare<option>quad9<option>custom</select> Secondary <select name=up_sec><option>quad9<option>cloudflare<option>custom<option>none</select></div>
<label><input type=checkbox name=up_doh> DoH fallback if port 853 is blocked</label>
<label><input type=checkbox name=up_plain> Plain DNS if every encrypted upstream is down</label>
<div class=row>Custom DoT <input name=up_cip size=14 placeholder=IP><input name=up_cip2 size=14 placeholder="IP 2"><input name=up_cname size=22 placeholder="TLS name"></div>
<label><input type=checkbox name=up_cdoh> Custom provider also serves DoH</label></fieldset>
<fieldset><legend>Privacy &amp; blocking</legend>
<label><input type=checkbox name=pad> Pad encrypted queries (RFC 8467)</label>
<label><input type=checkbox name=ad> Pass DNSSEC "validated" (AD) flag</label>
<label><input type=checkbox name=ff_canary> Stop Firefox bypassing via its own DoH</label>
<label><input type=checkbox name=icloud> Disable iCloud Private Relay on this network</label>
<label><input type=checkbox name=priv_rev> Answer private reverse lookups locally</label>
<div class=row>Blocked answer TTL <input name=blk_ttl size=5> s &nbsp; Time zone <input name=tz size=12> &nbsp; Log <select name=log><option value=0>error<option value=1>warn<option value=2>info<option value=3>debug</select></div>
<div class=row><button class=primary>Save settings</button><span class=dim>DNS changes restart the device.</span></div></fieldset></form>
<h2>DEVICE</h2><div class=grid2><div class=card><div id=dev></div><div class=row><button id=flush>Flush DNS cache</button><button id=reboot>Reboot</button><button id=forget>Forget Wi-Fi</button></div>
<div class=row><input type=file id=fwFile accept=.bin><button id=fwUpload>Flash firmware</button></div>
<div class=row><button id=upCheck>Check for updates</button><button id=upFlash class=primary hidden>Download &amp; flash</button><span id=upInfo class=dim></span></div></div>
<div class=card><b>Change password</b><div class=row><input id=pCur type=password placeholder=current autocomplete=current-password><input id=pNew type=password placeholder="new (10+)" autocomplete=new-password><button id=pSave>Change</button></div></div></div>
</div><div id=toast></div>
<script>
const $=id=>document.getElementById(id);
function toast(t,bad){const e=$('toast');e.textContent=t;e.className=bad?'bad':'';e.style.display='block';clearTimeout(e._t);e._t=setTimeout(()=>e.style.display='none',4000)}
async function api(path,data,body){
 const opt={method:'POST',credentials:'same-origin',headers:{'X-Requested-With':'adblock'}};
 if(body){opt.body=body}else{opt.headers['Content-Type']='application/x-www-form-urlencoded';opt.body=new URLSearchParams(data||{})}
 const r=await fetch(path,opt);const t=await r.text();toast(t||r.statusText,!r.ok);if(r.ok)load();return r.ok}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function rows(tbody,items,make){tbody.replaceChildren(...items.map(make));if(!items.length){const tr=el('tr');tr.append(el('td','none','dim'));tbody.append(tr)}}
function fmt(n){return Number(n).toLocaleString()}
function card(v,l){const c=el('div',undefined,'card');c.append(el('div',v,'v'),el('div',l,'l'));return c}
function pill(id,text,cls){const p=$(id);p.textContent=text;p.className='pill '+cls}
let cfgLoaded=false;
async function load(){
 let s;try{s=await (await fetch('/api/stats')).json()}catch(e){pill('pUp','offline','bad');return}
 $('ver').textContent='v'+s.version;
 pill('pBlock',s.blocking?'blocking on':(s.resumeIn?'paused ('+Math.ceil(s.resumeIn/60)+' min)':'paused'),s.blocking?'ok':'warn');
 const enc=s.upstreams.find(u=>u.encrypted&&u.state==='up');
 pill('pUp',s.plainFallback?'PLAIN DNS':(enc?'encrypted: '+enc.name:'encrypted DNS'),s.plainFallback?'bad':'ok');
 pill('pClock',s.timeSynced?s.now:'clock not synced',s.timeSynced?'dim':'warn');
 $('setup').hidden=!s.setupRequired;$('plainBanner').hidden=!s.plainFallback;
 const d=s.dns,pct=d.queries?Math.round(100*d.blocked/d.queries):0;
 $('cards').replaceChildren(card(fmt(d.queries),'queries'),card(fmt(d.blocked)+' ('+pct+'%)','blocked'),card(fmt(d.cacheHits),'cache hits'),
  card(fmt(s.blocklist.entries),'list domains'),card(fmt(s.clients.length),'clients'),card(s.uptime,'uptime'));
 rows($('ups').tBodies[0],s.upstreams,u=>{const tr=el('tr');tr.append(el('td',u.name),el('td',u.encrypted?'encrypted':'plain',u.encrypted?'ok':'warn'),
  el('td',u.state,u.state==='up'?'ok':(u.state==='down'?'bad':'dim')),el('td',fmt(u.ok)),el('td',fmt(u.failed)),el('td',u.latencyMs+' ms'));return tr});
 const bl=s.blocklist;$('blInfo').replaceChildren(el('div',fmt(bl.entries)+' domains '+(bl.inMemory?'in PSRAM':'served from flash')+', built '+bl.built),
  el('div','last update '+bl.lastAttempt+': '+bl.lastResult,bl.lastOk?'ok':'warn'));
 if(document.activeElement!==$('blUrl'))$('blUrl').value=bl.url;if(document.activeElement!==$('blTime'))$('blTime').value=bl.time;
 for(const [list,id] of [['block','ruleBlock'],['allow','ruleAllow']])rows($(id).tBodies[0],s.rules[list],d=>{const tr=el('tr'),b=el('button','remove');
  b.onclick=()=>api('/api/rules/remove',{list,d});const td=el('td');td.append(b);tr.append(el('td',d),td);return tr});
 rows($('clients').tBodies[0],s.clients,c=>{const tr=el('tr'),b=el('button',c.banned?'Unban':'Ban');b.onclick=()=>api('/api/clients/ban',{ip:c.ip});
  const td=el('td');td.append(b);tr.append(el('td',c.ip+(c.banned?' (banned)':''),c.banned?'bad':''),el('td',c.mac),el('td',fmt(c.blocked),'bad'),el('td',fmt(c.allowed),'ok'),td);return tr});
 $('dev').replaceChildren(el('div',s.hostname+'.local  '+s.ip+'  RSSI '+s.rssi+' dBm'),el('div','heap '+fmt(s.heap)+' B (min '+fmt(s.heapMin)+'), PSRAM free '+fmt(s.psram)+' B, '+s.temp+' °C','dim'));
 if(!cfgLoaded){cfgLoaded=true;const c=await (await fetch('/api/config')).json();for(const [k,v] of Object.entries(c)){const i=$('cfg').elements[k];if(!i)continue;if(i.type==='checkbox')i.checked=v;else i.value=v}}
}
document.querySelectorAll('[data-pause]').forEach(b=>b.onclick=()=>api('/api/blocking/pause',{s:b.dataset.pause}));
$('resume').onclick=()=>api('/api/blocking/resume');
document.querySelectorAll('[data-add]').forEach(b=>b.onclick=async()=>{const list=b.dataset.add,i=$(list==='block'?'addBlock':'addAllow');if(i.value.trim()&&await api('/api/rules/add',{list,d:i.value.trim()}))i.value=''});
$('blSave').onclick=()=>api('/api/blocklist/settings',{u:$('blUrl').value.trim(),t:$('blTime').value.trim()});
$('blNow').onclick=()=>api('/api/blocklist/update');
function upload(path,input){const f=$(input).files[0];if(!f)return toast('choose a file first',true);const fd=new FormData();fd.append('f',f);toast('uploading '+(f.size/1048576).toFixed(2)+' MB...');api(path,null,fd)}
$('blUpload').onclick=()=>upload('/api/blocklist/upload','blFile');
// Updates: the browser fetches update.json and the firmware from the update site
// (GitHub Pages: release downloads send no CORS headers), keeps it in memory and
// sends it through the normal upload, so the same health check and rollback apply.
let upd=null;
function verCmp(a,b){const p=v=>String(v).replace(/^v/,'').split(/[-+]/)[0].split('.').map(n=>parseInt(n,10)||0);const x=p(a),y=p(b);for(let i=0;i<3;i++){const d=(x[i]||0)-(y[i]||0);if(d)return d}return 0}
$('upCheck').onclick=async()=>{upd=null;$('upFlash').hidden=true;$('upInfo').textContent='checking...';
 try{const s=await (await fetch('/api/stats')).json();const r=await fetch(s.updateUrl+'update.json',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const j=await r.json();
 if(!j.version||!j.firmware||!(j.size>0))throw Error('bad update.json');
 if(verCmp(j.version,s.version)>0){upd=Object.assign({},j,{base:s.updateUrl});$('upInfo').textContent='v'+j.version+' available (running v'+s.version+')';$('upFlash').hidden=false}
 else $('upInfo').textContent='up to date (v'+s.version+')'}
 catch(e){$('upInfo').textContent='';toast('update check failed: '+e.message,true)}};
$('upFlash').onclick=async()=>{if(!upd)return;
 if(!confirm('Download v'+upd.version+' ('+(upd.size/1048576).toFixed(2)+' MB) and flash it? The device reboots and rolls back if the new firmware is unhealthy.'))return;
 try{$('upInfo').textContent='downloading v'+upd.version+'...';const r=await fetch(new URL(upd.firmware,upd.base),{cache:'no-store'});if(!r.ok)throw Error('download HTTP '+r.status);
 const buf=await r.arrayBuffer();if(buf.byteLength!==upd.size)throw Error('downloaded '+buf.byteLength+' bytes, expected '+upd.size);
 if(new Uint8Array(buf)[0]!==0xE9)throw Error('not an ESP32 firmware image');
 const fd=new FormData();fd.append('f',new Blob([buf],{type:'application/octet-stream'}),'firmware-esp32s3-v'+upd.version+'.bin');
 $('upInfo').textContent='uploading v'+upd.version+' to the device...';if(await api('/api/firmware',null,fd)){$('upInfo').textContent='v'+upd.version+' installed, rebooting...';$('upFlash').hidden=true}else $('upInfo').textContent=''}
 catch(e){$('upInfo').textContent='';toast('update failed: '+e.message,true)}};
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
