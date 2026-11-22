"""Localhost control panel — Launch | History | Diff.

Three-tab interface. Stdlib only (http.server + threads + queue), zero new deps.
Binds to 127.0.0.1 by default; for Docker use --web-host 0.0.0.0.
"""
from __future__ import annotations

import asyncio
import json
import queue
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .capabilities import detect
from .config import Config, LLMConfig, SCAN_PROFILES, Scope, TargetCreds
from .history import RunHistory, RunRecord
from .inputs import load_seeds
from . import keys as keymod

_RUNS: dict[str, dict] = {}
_TOKEN = secrets.token_urlsafe(16)


def _default_runner():
    from .pipeline import run
    return run


# ── HTML ────────────────────────────────────────────────────────────────────
_CSS = """
:root{--bg:#12161d;--panel:#0d1117;--line:#2a3340;--ink:#d4d9e0;--dim:#8592a3;
      --acc:#cf9648;--red:#c65b4e;--green:#4a9e6b;--blue:#6f97c4;--mag:#b07cc6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:ui-monospace,"JetBrains Mono",monospace;font-size:13px;line-height:1.6}
.wrap{max-width:1140px;margin:0 auto;padding:20px 20px 80px}
h1{font-family:Georgia,serif;font-weight:500;font-size:26px;margin:0 0 2px}
.sub{color:var(--dim);margin:0 0 18px;font-size:12px}
/* tabs */
.tabs{display:flex;gap:0;border-bottom:1px solid var(--line);margin-bottom:22px}
.tab{background:0;border:0;border-bottom:2px solid transparent;padding:9px 20px;
  color:var(--dim);cursor:pointer;font:inherit;font-size:12px;letter-spacing:.08em;
  text-transform:uppercase;margin-bottom:-1px}
.tab.on{color:var(--acc);border-bottom-color:var(--acc)}
.tab:hover{color:var(--ink)}
/* layout */
.grid{display:grid;grid-template-columns:300px 1fr;gap:20px;align-items:start}
.card{background:var(--panel);border:1px solid var(--line);padding:16px;margin-bottom:16px}
.card h2{font-family:Georgia,serif;font-size:15px;margin:0 0 12px;font-weight:500}
label{display:block;color:var(--dim);margin:10px 0 3px;font-size:11px;
  letter-spacing:.08em;text-transform:uppercase}
input,select,textarea{width:100%;background:#0a0d12;border:1px solid var(--line);
  color:var(--ink);padding:7px 9px;font:inherit;font-size:12px;border-radius:2px}
textarea{min-height:68px;resize:vertical}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;align-items:center}
.row label{margin:0;display:flex;align-items:center;gap:5px;text-transform:none;
  letter-spacing:0;font-size:12px;color:var(--ink);width:auto}
.row input[type=checkbox]{width:auto}
button{background:var(--acc);color:#12161d;border:0;padding:8px 14px;font:inherit;
  font-weight:600;font-size:12px;cursor:pointer;border-radius:2px;margin-top:12px}
button.ghost{background:0;color:var(--ink);border:1px solid var(--line);margin-top:0}
button.danger{background:0;color:var(--red);border:1px solid var(--red)}
button.green{background:var(--green);color:#0a0d12}
button:disabled{opacity:.4;cursor:default}
/* chips */
.tools{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
.chip{padding:2px 7px;border:1px solid var(--line);border-radius:10px;font-size:11px}
.chip.on{border-color:#3f6d4e;color:#7fbf95}.chip.off{color:var(--dim)}
/* log */
#log{background:#0a0d12;border:1px solid var(--line);padding:10px;height:340px;
  overflow:auto;white-space:pre-wrap;font-size:11.5px}
#log .rce{color:var(--red)}#log .data{color:var(--blue)}#log .dim{color:var(--dim)}
#log .grn{color:var(--green)}
/* leads */
.lead{border-bottom:1px solid rgba(42,51,64,.45);padding:8px 0}
.lead .t{color:var(--dim);font-size:11px;margin-top:2px}
.pri{color:var(--acc);font-weight:600;min-width:28px}
/* history table */
.htbl{width:100%;border-collapse:collapse}
.htbl th{text-align:left;color:var(--dim);font-size:11px;letter-spacing:.06em;
  text-transform:uppercase;padding:6px 10px;border-bottom:1px solid var(--line)}
.htbl td{padding:7px 10px;border-bottom:1px solid rgba(42,51,64,.35);vertical-align:top}
.htbl tr:hover td{background:rgba(255,255,255,.02);cursor:pointer}
.htbl tr.open td{background:rgba(255,255,255,.03)}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;
  border:1px solid currentColor;margin-right:4px}
.badge.passive{color:var(--dim)}.badge.active{color:var(--blue)}
.badge.nuclei{color:var(--mag)}.badge.stealth{color:var(--green)}
.badge.balanced{color:var(--acc)}.badge.aggressive{color:var(--red)}
.badge.rce{color:var(--red)}.badge.takeover{color:var(--red)}
.badge.creds{color:var(--acc)}.badge.foothold{color:var(--acc)}
.badge.data{color:var(--blue)}.badge.recon{color:var(--dim)}
.expanded-leads{padding:10px 10px 4px;background:#0a0d12;
  border-bottom:1px solid var(--line)}
/* diff */
.diff-bar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:18px}
.diff-sel{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.diff-sel select{width:340px}
.diff-sec{margin-bottom:22px}
.diff-sec h3{font-family:Georgia,serif;font-size:15px;font-weight:500;margin:0 0 10px;
  display:flex;align-items:center;gap:10px}
.diff-sec h3 .cnt{font-size:12px;color:var(--dim);font-family:inherit;font-weight:400}
.dlead{padding:9px 0 9px 14px;border-left:3px solid var(--line);
  border-bottom:1px solid rgba(42,51,64,.3);margin-bottom:2px}
.dlead.new{border-left-color:var(--green)}
.dlead.resolved{border-left-color:var(--red);opacity:.6}
.dlead.changed{border-left-color:var(--acc)}
.dlead .dt{color:var(--dim);font-size:11px;margin-top:3px}
.chg{font-size:11px;margin-top:4px;color:var(--acc)}
.chg .from{color:var(--dim);text-decoration:line-through}
.sum-bar{background:var(--panel);border:1px solid var(--line);padding:10px 14px;
  margin-bottom:20px;font-size:12px;display:flex;gap:20px;flex-wrap:wrap}
.sum-bar span{display:flex;align-items:center;gap:5px}
@media(max-width:800px){.grid{grid-template-columns:1fr}.diff-sel select{width:100%}}
"""

_JS = r"""
const T="__TOKEN__";
let _rid=null;
function h(u,o={}){
  o.headers=Object.assign({'X-Token':T,'Content-Type':'application/json'},o.headers||{});
  return fetch(u,o);
}
// ── tabs ────────────────────────────────────────────────────────────────
function tab(name){
  ['launch','history','diff'].forEach(n=>{
    document.getElementById('p-'+n).style.display=n===name?'':'none';
    document.getElementById('t-'+n).classList.toggle('on',n===name);
  });
  if(name==='history') loadHistory();
  if(name==='diff') loadDiffSelectors();
}
// ── status ──────────────────────────────────────────────────────────────
async function status(){
  const s=await(await h('/api/status')).json();
  document.getElementById('tools').innerHTML=
    s.tools.map(t=>`<span class="chip ${t.present?'on':'off'}">${t.name}</span>`).join('');
  document.getElementById('keys').innerHTML=
    Object.entries(s.keys).map(([k,v])=>
      `<span class="chip ${v?'on':'off'}">${k.replace(/_API_KEY|_KEY|_TOKEN/,'')}</span>`
    ).join('');
}
async function savekey(){
  const name=k_name.value.trim(),val=k_val.value;
  if(!name)return;
  await h('/api/keys',{method:'POST',body:JSON.stringify({[name]:val})});
  k_val.value=''; status();
}
// ── launch ──────────────────────────────────────────────────────────────
function appendLog(msg,cls){
  const el=document.createElement('span');
  if(cls)el.className=cls; el.textContent=msg;
  log.appendChild(el); log.scrollTop=log.scrollHeight;
}
async function stopScan(){
  if(!_rid)return;
  await h('/api/stop/'+_rid,{method:'POST'});
  appendLog('\n■ Stop requested…\n','dim');
  document.getElementById('stopbtn').disabled=true;
}
function launch(){
  const body={targets:targets.value,profile:profile.value,active:active.checked,
    nuclei:nuclei.checked,offline:offline.checked,llm:llm.checked,
    scope:scope.value,bearer:bearer.value,cookie:cookie.value,rf:rf.checked};
  log.innerHTML=''; leads.innerHTML=''; links.innerHTML='';
  document.getElementById('stopbtn').style.display='none';
  document.getElementById('spin').textContent='';
  h('/api/run',{method:'POST',body:JSON.stringify(body)}).then(r=>r.json())
  .then(({run_id,error})=>{
    if(error){appendLog('error: '+error+'\n','rce');return;}
    _rid=run_id;
    document.getElementById('stopbtn').style.display='';
    document.getElementById('stopbtn').disabled=false;
    document.getElementById('spin').textContent='⏳ running…';
    const es=new EventSource('/api/stream/'+run_id+'?t='+T);
    es.onmessage=e=>{
      const m=JSON.parse(e.data);
      if(m.type==='start'){appendLog('▶ '+m.collector+' — '+m.detail+'\n','dim');}
      else if(m.type==='progress'){
        appendLog((m.count>0?'✔ ':'· ')+m.collector+': '+m.detail+'\n',m.count>0?'grn':'dim');
      }
      else if(m.type==='scope_skip'){appendLog('⚠ '+m.message+'\n','dim');}
      else if(m.type==='note'){appendLog('  ↳ '+m.message+'\n','dim');}
      else if(m.type==='lead'){
        const c=m.impact==='RCE'||m.impact==='Takeover'?'rce':m.impact==='Data'?'data':'';
        appendLog('⚡ '+m.impact+'/'+m.exploitability+' ['+m.priority+'] '
          +m.title+' — '+m.asset+'\n',c);
        leads.innerHTML+=`<div class=lead><span class=pri>${m.priority}</span>&nbsp;
          <span class="${c||''}">${m.impact}/${m.exploitability}</span>&nbsp;${m.title}
          <div class=t>${m.asset} — ${m.move||''}</div></div>`;
      }
      else if(m.type==='done'){
        appendLog('\n✔ '+m.headline+'\n');
        appendLog('  '+m.stats+'\n','dim');
        document.getElementById('spin').textContent='';
        document.getElementById('stopbtn').style.display='none';
        links.innerHTML=`<a href="/report/${run_id}.html" target=_blank>HTML report</a>
          &nbsp;·&nbsp;<a href="/report/${run_id}.json">JSON</a>`;
        es.close();
      }
      else if(m.type==='error'){
        appendLog('\n! '+m.message+'\n','rce');
        document.getElementById('spin').textContent='';
        document.getElementById('stopbtn').style.display='none';
        es.close();
      }
    };
  });
}
// ── history ─────────────────────────────────────────────────────────────
let _openRow=null;
async function loadHistory(){
  const tbl=document.getElementById('run-rows');
  tbl.innerHTML='<tr><td colspan=7 style="color:var(--dim)">Loading…</td></tr>';
  const runs=await(await h('/api/runs')).json();
  if(!runs.length){
    tbl.innerHTML='<tr><td colspan=7 style="color:var(--dim)">No scans recorded yet.</td></tr>';
    return;
  }
  tbl.innerHTML=runs.map(r=>rowHtml(r)).join('');
}
function rowHtml(r){
  const d=new Date(r.started_at*1000);
  const ts=d.toISOString().slice(0,16).replace('T',' ');
  const dur=r.duration_s?` (${r.duration_s}s)`:'';
  const modeBadge=`<span class="badge ${r.mode.includes('nuclei')?'nuclei':r.mode.split('/')[0]}">${r.mode}</span>`;
  const profBadge=`<span class="badge ${r.profile}">${r.profile}</span>`;
  const imp=r.top_impact.toLowerCase().replace(' ','');
  const impBadge=r.top_impact?`<span class="badge ${imp}">${r.top_impact}</span>`:'—';
  return `<tr id="row-${r.run_id}" onclick="toggleRow('${r.run_id}')">
    <td>${ts}${dur}</td>
    <td>${r.target}</td>
    <td>${modeBadge}${profBadge}</td>
    <td>${r.lead_count} <span style="color:var(--dim);font-size:11px">(${r.confirmed}✔)</span></td>
    <td>${impBadge}</td>
    <td>
      <button class=ghost onclick="event.stopPropagation();diffVsPrev('${r.run_id}','${r.target}')">Diff vs prev</button>
      &nbsp;
      <button class=danger onclick="event.stopPropagation();deleteRun('${r.run_id}')">✕</button>
    </td>
  </tr>
  <tr id="exp-${r.run_id}" style="display:none">
    <td colspan=6 style="padding:0">
      <div class=expanded-leads id="leads-${r.run_id}">Loading…</div>
    </td>
  </tr>`;
}
async function toggleRow(rid){
  const exp=document.getElementById('exp-'+rid);
  if(exp.style.display!=='none'){exp.style.display='none';return;}
  exp.style.display='';
  const el=document.getElementById('leads-'+rid);
  el.textContent='Loading…';
  const run=await(await h('/api/runs/'+rid)).json();
  if(!run.leads||!run.leads.length){el.textContent='No leads stored.';return;}
  el.innerHTML=run.leads.map(l=>{
    const c=l.impact==='RCE'||l.impact==='Takeover'?'rce':l.impact==='Data'?'data':'';
    return `<div class=lead><span class=pri>${l.priority}</span>&nbsp;
      <span class="${c||''}">${l.impact}/${l.exploitability}</span>&nbsp;${l.title}
      <div class=t>${l.asset}${l.move?' — '+l.move:''}</div></div>`;
  }).join('');
}
async function deleteRun(rid){
  if(!confirm('Delete this run record?'))return;
  await h('/api/runs/'+rid,{method:'DELETE'});
  loadHistory();
}
async function diffVsPrev(rid,target){
  tab('diff');
  const res=await(await h('/api/diff/auto?target='+encodeURIComponent(target)+'&anchor='+rid)).json();
  if(res.error){alert(res.error);return;}
  renderDiff(res);
}
// ── diff ────────────────────────────────────────────────────────────────
async function loadDiffSelectors(){
  const runs=await(await h('/api/runs')).json();
  const targets=[...new Set(runs.map(r=>r.target))];
  const makeOpts=sel=>runs.map(r=>`<option value="${r.run_id}">[${r.started_iso}] ${r.target} — ${r.lead_count} leads</option>`).join('');
  document.getElementById('diff-a').innerHTML=makeOpts();
  document.getElementById('diff-b').innerHTML=makeOpts();
  // default B to index 0, A to index 1
  if(runs.length>1)document.getElementById('diff-a').selectedIndex=1;
  document.getElementById('auto-target').innerHTML=
    targets.map(t=>`<option>${t}</option>`).join('');
}
async function doDiff(){
  const a=document.getElementById('diff-a').value;
  const b=document.getElementById('diff-b').value;
  if(a===b){alert('Select two different runs.');return;}
  const res=await(await h(`/api/diff?a=${a}&b=${b}`)).json();
  if(res.error){alert(res.error);return;}
  renderDiff(res);
}
async function doAutoDiff(){
  const target=document.getElementById('auto-target').value;
  const res=await(await h('/api/diff/auto?target='+encodeURIComponent(target))).json();
  if(res.error){alert(res.error);return;}
  renderDiff(res);
}
function renderDiff(d){
  const el=document.getElementById('diff-result');
  if(!d||d.error){el.innerHTML=`<p style="color:var(--red)">${d?d.error:'No data'}</p>`;return;}
  const ra=d.run_a, rb=d.run_b;
  let html=`<div class=sum-bar>
    <strong>${ra.target}</strong>
    <span>📅 ${ra.started_iso} → ${rb.started_iso}</span>
    <span style="color:var(--green)">▲ ${d.new_leads.length} new</span>
    <span style="color:var(--red)">▼ ${d.resolved_leads.length} resolved</span>
    <span style="color:var(--acc)">~ ${d.changed_leads.length} changed</span>
    <span style="color:var(--dim)">${d.unchanged_count} unchanged</span>
  </div>`;
  if(!d.new_leads.length&&!d.resolved_leads.length&&!d.changed_leads.length){
    html+='<p style="color:var(--dim)">No differences between these two runs.</p>';
  }
  if(d.new_leads.length){
    html+=`<div class=diff-sec><h3>🟢 New <span class=cnt>${d.new_leads.length} lead${d.new_leads.length!==1?'s':''} not seen before</span></h3>`;
    html+=d.new_leads.map(l=>dleadHtml(l,'new')).join('');
    html+=`</div>`;
  }
  if(d.resolved_leads.length){
    html+=`<div class=diff-sec><h3>🔴 Resolved <span class=cnt>${d.resolved_leads.length} lead${d.resolved_leads.length!==1?'s':''} no longer detected</span></h3>`;
    html+=d.resolved_leads.map(l=>dleadHtml(l,'resolved')).join('');
    html+=`</div>`;
  }
  if(d.changed_leads.length){
    html+=`<div class=diff-sec><h3>🟡 Changed <span class=cnt>${d.changed_leads.length} lead${d.changed_leads.length!==1?'s':''} with updated rating</span></h3>`;
    html+=d.changed_leads.map(l=>dleadHtml(l,'changed')).join('');
    html+=`</div>`;
  }
  el.innerHTML=html;
}
function dleadHtml(l,cls){
  const c=l.impact==='RCE'||l.impact==='Takeover'?'rce':l.impact==='Data'?'data':'';
  let chgHtml='';
  if(l.changes){
    chgHtml='<div class=chg>'+Object.entries(l.changes).map(([f,v])=>
      `${f}: <span class=from>${v.from}</span> → <strong>${v.to}</strong>`
    ).join(' &nbsp;')+'</div>';
  }
  return `<div class="dlead ${cls}">
    <span class=pri>${l.priority}</span>&nbsp;
    <span class="${c||''}">${l.impact}/${l.exploitability}</span>&nbsp;<strong>${l.title}</strong>
    <div class=dt>${l.asset}${l.zone?' ['+l.zone+']':''}</div>
    ${l.move?`<div class=dt>↳ ${l.move}</div>`:''}
    ${chgHtml}
  </div>`;
}
status();
"""

_PAGE_TEMPLATE = """<!doctype html><html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Bastion — control</title>
<style>__CSS__</style></head><body><div class=wrap>
<h1>Bastion</h1>
<p class=sub>the scout that maps the castle · localhost only · __HOST__:__PORT__</p>
<div class=tabs>
  <button class="tab on" id=t-launch onclick="tab('launch')">Launch</button>
  <button class=tab id=t-history onclick="tab('history')">History</button>
  <button class=tab id=t-diff onclick="tab('diff')">Diff</button>
</div>
<!-- ═══ LAUNCH ════════════════════════════════════════════════════════ -->
<div id=p-launch>
 <div class=grid>
  <div>
   <div class=card><h2>Engagement</h2>
    <label>Targets (domain / URL / IP / CIDR, one per line)</label>
    <textarea id=targets placeholder="example.com&#10;10.0.0.0/24"></textarea>
    <label>Scan mode</label>
    <select id=profile>
      <option>stealth</option><option selected>balanced</option><option>aggressive</option>
    </select>
    <div class=row>
      <label><input type=checkbox id=active> active</label>
      <label><input type=checkbox id=nuclei> nuclei</label>
      <label><input type=checkbox id=offline> offline</label>
      <label><input type=checkbox id=llm> llm</label>
      <label><input type=checkbox id=rf> RF recon</label>
    </div>
    <label>Scope file (required for active)</label>
    <input id=scope placeholder="/path/to/scope.txt">
    <label>Bearer token (grey-box)</label>
    <input id=bearer placeholder="eyJhbGci…">
    <label>Cookie (grey-box)</label>
    <input id=cookie placeholder="session=abc; csrf=xyz">
    <button onclick=launch()>▶ Launch scan</button>
   </div>
   <div class=card><h2>Tooling</h2><div class=tools id=tools>…</div>
    <h2 style=margin-top:14px>Keys</h2><div class=tools id=keys>…</div>
    <div class=row style=margin-top:10px>
      <input id=k_name placeholder="KEY_NAME" style=flex:1>
      <input id=k_val placeholder="value" type=password style=flex:1>
      <button class=ghost onclick=savekey() style=margin-top:0>Save</button>
    </div>
   </div>
  </div>
  <div class=card><h2>Live&nbsp;<span id=spin style="font-size:11px;color:var(--dim)"></span></h2>
   <div id=log></div>
   <div style="margin-top:10px;display:flex;gap:10px;align-items:center">
    <button id=stopbtn class=ghost style="display:none;color:var(--red);border-color:var(--red)"
      onclick=stopScan()>■ Stop</button>
    <span id=links></span>
   </div>
   <h2 style=margin-top:16px>Leads</h2>
   <div id=leads></div>
  </div>
 </div>
</div>
<!-- ═══ HISTORY ══════════════════════════════════════════════════════ -->
<div id=p-history style=display:none>
 <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
  <span style="color:var(--dim);font-size:12px">Click a row to expand leads · runs stored locally in SQLite</span>
  <button class=ghost onclick=loadHistory()>↺ Refresh</button>
 </div>
 <table class=htbl>
  <thead><tr>
   <th>Time</th><th>Target</th><th>Mode / Profile</th>
   <th>Leads</th><th>Top impact</th><th>Actions</th>
  </tr></thead>
  <tbody id=run-rows></tbody>
 </table>
</div>
<!-- ═══ DIFF ════════════════════════════════════════════════════════ -->
<div id=p-diff style=display:none>
 <div class=card><h2>Auto-diff — latest vs previous for a target</h2>
  <div class=row style=align-items:flex-end>
   <div style=flex:1><label>Target</label><select id=auto-target></select></div>
   <button class=green onclick=doAutoDiff() style=margin-top:0>Compare latest two</button>
  </div>
 </div>
 <div class=card><h2>Manual diff — pick any two runs</h2>
  <div class=diff-sel>
   <div><label>Run A (baseline / older)</label><select id=diff-a></select></div>
   <div><label>Run B (current / newer)</label><select id=diff-b></select></div>
   <button class=green onclick=doDiff() style=margin-top:auto>Compare</button>
  </div>
 </div>
 <div id=diff-result></div>
</div>
<script>__JS__</script>
</div></body></html>"""


def _build_page(host: str, port: int) -> str:
    return (_PAGE_TEMPLATE
            .replace("__CSS__", _CSS)
            .replace("__JS__", _JS.replace("__TOKEN__", _TOKEN))
            .replace("__HOST__", host)
            .replace("__PORT__", str(port)))


# ── HTTP handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "bastion-ui"

    def log_message(self, *a):
        pass

    def _tok_ok(self) -> bool:
        q = parse_qs(urlparse(self.path).query)
        return (self.headers.get("X-Token") == _TOKEN
                or q.get("t", [None])[0] == _TOKEN)

    def _json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)

        if path == "/":
            body = self.server.page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not self._tok_ok():
            self._json({"error": "bad token"}, 403)
            return

        if path == "/api/status":
            self._json(self._status())
        elif path == "/api/runs":
            runs = self.server.history.list_runs()
            self._json([r.to_meta() for r in runs])
        elif path.startswith("/api/runs/"):
            rid = path.rsplit("/", 1)[-1]
            rec = self.server.history.get_run(rid)
            self._json(rec.to_meta() | {"leads": rec.leads} if rec
                       else {"error": "not found"}, 200 if rec else 404)
        elif path == "/api/diff":
            a_id, b_id = qs.get("a", [None])[0], qs.get("b", [None])[0]
            self._json(self._diff(a_id, b_id))
        elif path == "/api/diff/auto":
            target = qs.get("target", [None])[0]
            anchor = qs.get("anchor", [None])[0]
            self._json(self._auto_diff(target, anchor))
        elif path.startswith("/api/stream/"):
            self._stream(path.rsplit("/", 1)[-1])
        elif path.startswith("/report/"):
            self._report(path)
        else:
            self._json({"error": "not found"}, 404)

    # ── POST / DELETE ────────────────────────────────────────────────────────
    def do_DELETE(self) -> None:
        if not self._tok_ok():
            self._json({"error": "bad token"}, 403)
            return
        path = urlparse(self.path).path
        if path.startswith("/api/runs/"):
            rid = path.rsplit("/", 1)[-1]
            ok = self.server.history.delete(rid)
            self._json({"ok": ok}, 200 if ok else 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if not self._tok_ok():
            self._json({"error": "bad token"}, 403)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json({"error": "bad json"}, 400)
            return
        path = urlparse(self.path).path
        if path == "/api/keys":
            self._save_keys(data)
        elif path == "/api/run":
            self._json(self._start_run(data))
        elif path.startswith("/api/stop/"):
            rid = path.rsplit("/", 1)[-1]
            run = _RUNS.get(rid)
            if run and run.get("stop"):
                run["stop"].set()
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)
        else:
            self._json({"error": "not found"}, 404)

    # ── handlers ─────────────────────────────────────────────────────────────
    def _status(self) -> dict:
        caps = detect()
        cfg = self.server.cfg
        from .keys import KEY_SPECS, status as key_status
        return {
            "tools": [{"name": t, "present": caps.has(t)} for t in _display_tools()],
            "keys": key_status(cfg.keys_path),
        }

    def _save_keys(self, data: dict) -> None:
        cfg = self.server.cfg
        existing = keymod.load_env_file(cfg.keys_path)
        existing.update({k: v for k, v in data.items() if k})
        keymod.write_env_file(cfg.keys_path, existing)
        self._json({"ok": True})

    def _start_run(self, data: dict) -> dict:
        seeds_raw = [t for t in data.get("targets", "").splitlines() if t.strip()]
        try:
            seeds, warns = load_seeds(seeds_raw, None)
        except Exception as exc:
            return {"error": str(exc)}
        if not seeds:
            return {"error": "no valid targets"}

        want_active = bool(data.get("active") or data.get("nuclei"))
        cfg = self.server.cfg
        run_cfg = Config(cache_path=cfg.cache_path, keys_path=cfg.keys_path)
        run_cfg.offline = bool(data.get("offline"))
        run_cfg.profile = SCAN_PROFILES.get(data.get("profile", "balanced"),
                                             SCAN_PROFILES["balanced"])
        run_cfg.allow_active = want_active
        run_cfg.run_nuclei = bool(data.get("nuclei"))
        run_cfg.rf_authorized = bool(data.get("rf"))
        run_cfg.target_creds = TargetCreds(
            bearer=data.get("bearer") or None,
            cookie=data.get("cookie") or None)
        if data.get("llm"):
            run_cfg.llm = LLMConfig.from_env()
            run_cfg.llm.enabled = True
        if want_active:
            scope = data.get("scope", "").strip()
            if not scope:
                return {"error": "active mode needs a scope file path"}
            try:
                run_cfg.scope = Scope.load(scope)
            except Exception as exc:
                return {"error": f"scope: {exc}"}

        run_id = uuid.uuid4().hex[:12]
        q: queue.Queue = queue.Queue()
        stop_evt = threading.Event()
        _RUNS[run_id] = {"q": q, "done": False, "stop": stop_evt}
        threading.Thread(
            target=self.server.run_worker,
            args=(run_id, seeds, run_cfg, want_active, q, stop_evt),
            daemon=True).start()
        return {"run_id": run_id}

    def _diff(self, a_id: str | None, b_id: str | None) -> dict:
        if not a_id or not b_id:
            return {"error": "provide a and b run IDs"}
        rec_a = self.server.history.get_run(a_id)
        rec_b = self.server.history.get_run(b_id)
        if not rec_a or not rec_b:
            return {"error": "one or both runs not found"}
        from .diff import diff_runs
        return diff_runs(rec_a, rec_b).to_dict()

    def _auto_diff(self, target: str | None, anchor: str | None) -> dict:
        if not target:
            return {"error": "provide a target"}
        runs = self.server.history.runs_for_target(target, limit=20)
        if anchor:
            # anchor is "current" run; find the one before it
            ids = [r.run_id for r in runs]
            try:
                idx = ids.index(anchor)
                if idx + 1 >= len(runs):
                    return {"error": "no previous run for this target"}
                pair = (runs[idx + 1], runs[idx])  # older, newer
            except ValueError:
                return {"error": "anchor run not found for this target"}
        else:
            if len(runs) < 2:
                return {"error": f"need at least 2 runs for '{target}'"}
            pair = (runs[1], runs[0])  # older first, newer second

        rec_a = self.server.history.get_run(pair[0].run_id)
        rec_b = self.server.history.get_run(pair[1].run_id)
        if not rec_a or not rec_b:
            return {"error": "runs not found"}
        from .diff import diff_runs
        return diff_runs(rec_a, rec_b).to_dict()

    def _stream(self, run_id: str) -> None:
        run = _RUNS.get(run_id)
        if not run:
            self._json({"error": "unknown run"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = run["q"]
        while True:
            try:
                evt = q.get(timeout=30)
            except queue.Empty:
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                except OSError:
                    break
            try:
                self.wfile.write(f"data: {json.dumps(evt)}\n\n".encode())
                self.wfile.flush()
            except OSError:
                break
            if evt.get("type") in ("done", "error"):
                break

    def _report(self, path: str) -> None:
        name = path.rsplit("/", 1)[-1]
        run_id, _, ext = name.partition(".")
        run = _RUNS.get(run_id)
        if not run or not run.get("done"):
            self._json({"error": "not ready"}, 404)
            return
        body = (run.get("json", "{}") if ext == "json" else
                run.get("html", "<h1>no report</h1>")).encode()
        ctype = "application/json" if ext == "json" else "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _display_tools() -> list[str]:
    return ["subfinder", "naabu", "nuclei", "httpx", "nmap", "masscan",
            "smbclient", "netexec", "bluetoothctl", "amass", "ffuf"]


# ── server ────────────────────────────────────────────────────────────────────
class UIServer(ThreadingHTTPServer):
    def __init__(self, addr: tuple, cfg: Config, runner=None):
        super().__init__(addr, Handler)
        self.cfg = cfg
        self._runner = runner or _default_runner()
        self.history = RunHistory(cfg.cache_path)
        self.page = _build_page(addr[0], addr[1])

    def run_worker(self, run_id: str, seeds, run_cfg: Config,
                   want_active: bool, q: queue.Queue,
                   stop_evt: threading.Event | None = None) -> None:
        import time as _t
        from .report import render_html, render_json
        started = _t.time()

        def on_progress(name: str, n: int, detail: str = "") -> None:
            q.put({"type": "start" if n == 0 else "progress",
                   "collector": name, "count": n, "detail": detail})

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            amap, meta, sources, elapsed, synth = loop.run_until_complete(
                self._runner(seeds, run_cfg, want_active=want_active,
                             on_progress=on_progress, stop_event=stop_evt))

            # emit skip notes
            for note in (meta.get("notes") or []):
                q.put({"type": "note", "message": note})
            # emit leads live
            for lead in amap.leads[:80]:
                q.put({"type": "lead", "title": lead.title,
                       "asset": lead.asset_key, "impact": lead.impact.label,
                       "exploitability": lead.exploitability.label,
                       "priority": lead.priority, "move": lead.move})

            mode = ("active" if want_active else "passive") + \
                   ("/offline" if run_cfg.offline else "")
            html = render_html(amap, mode=mode, sources=sources,
                               synth=synth, elapsed=elapsed)
            js = render_json(amap, mode=mode, sources=sources, synth=synth)
            _RUNS[run_id]["html"] = html
            _RUNS[run_id]["json"] = js
            _RUNS[run_id]["done"] = True

            g = amap.graph.stats()
            stats_line = (f"{g.get('host',0)} names · {g.get('live_hosts',0)} live · "
                          f"{g.get('ip',0)} IPs · {g.get('service',0)} services · "
                          f"{len(amap.leads)} leads in {elapsed:.1f}s")

            # ── persist to history ──────────────────────────────────────
            top = (max((l.impact for l in amap.leads), default=None)
                   if amap.leads else None)
            lead_dicts = [{
                "fingerprint": l.fingerprint, "zone": l.zone.value,
                "title": l.title, "asset": l.asset_key,
                "impact": l.impact.label, "exploitability": l.exploitability.label,
                "priority": l.priority, "move": l.move, "detail": l.detail,
                "confidence": l.confidence.value, "source_tool": l.source_tool,
                "refs": l.refs,
            } for l in amap.leads]

            record = RunRecord(
                run_id=run_id,
                target=amap.target,
                started_at=started,
                finished_at=_t.time(),
                mode=mode,
                profile=run_cfg.profile.name,
                knowledge=run_cfg.knowledge.value,
                lead_count=len(amap.leads),
                confirmed=amap.confirmed,
                top_impact=top.label if top else "",
                sources=sources,
                leads=lead_dicts,
                headline=amap.headline,
                stats_line=stats_line,
            )
            self.history.save(record)

            q.put({"type": "done", "headline": amap.headline, "stats": stats_line})

        except Exception as exc:
            _RUNS[run_id]["done"] = True
            q.put({"type": "error", "message": str(exc)})
            import traceback; traceback.print_exc()


# ── entrypoint ────────────────────────────────────────────────────────────────
def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8899,
          runner=None) -> None:
    srv = UIServer((host, port), cfg, runner=runner)
    url = f"http://{host}:{port}/"
    print(f"\n  Bastion control panel → {url}")
    print(f"  Scan history stored in: {cfg.cache_path}")
    print(f"  (Ctrl+C to stop)\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down.")
        srv.shutdown()
