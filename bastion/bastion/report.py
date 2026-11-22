"""Output layers. Terminal-first, then NDJSON to pipe, then HTML to share.

The HTML fort plan is reframed for the attacker: wall colour = best impact
reachable at that zone, breaches (dashed gaps) mark where you get in, and
assault arrows point at the strongest avenues.
"""
from __future__ import annotations

import html as _html
import json
import math
import sys
from datetime import datetime, timezone

from .castle import AttackMap
from .models import (Avenue, Exploitability, Impact, Lead, PLAN_ZONES, Zone,
                     ZONE_INTENT, ZONE_LABEL)

# --- ANSI ------------------------------------------------------------------
_C = {"reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
      "red": "\033[38;5;203m", "amber": "\033[38;5;214m",
      "green": "\033[38;5;115m", "blue": "\033[38;5;74m",
      "grey": "\033[38;5;245m", "white": "\033[38;5;253m",
      "mag": "\033[38;5;176m"}

_IMPACT_COLOR = {
    Impact.RCE: "red", Impact.TAKEOVER: "red", Impact.CREDENTIALS: "amber",
    Impact.FOOTHOLD: "amber", Impact.DATA: "blue", Impact.RECON: "grey",
}


def _c(txt: str, color: str, on: bool) -> str:
    if not on:
        return txt
    return f"{_C.get(color, '')}{txt}{_C['reset']}"


def render_terminal(amap: AttackMap, *, synth: dict | None = None,
                    color: bool | None = None, top: int = 25) -> str:
    on = sys.stdout.isatty() if color is None else color
    L = []
    b = lambda t: _c(t, "bold", on)  # noqa: E731

    L.append("")
    L.append(_c("  BASTION", "bold", on) + _c(f"  scout's report · {amap.target} · "
             f"{amap.knowledge}-box", "grey", on))
    L.append(_c("  " + "─" * 66, "grey", on))
    L.append("  " + amap.headline)
    L.append("")

    # impact tally
    tally = amap.leads_by_impact()
    cells = []
    for imp in reversed(list(Impact)):
        n = tally[imp.label]
        if n:
            cells.append(_c(f"{imp.label}:{n}", _IMPACT_COLOR[imp], on))
    if cells:
        L.append("  " + "   ".join(cells))
        L.append("")

    # avenues
    L.append(b("  AVENUES OF APPROACH") + _c("  (ranked)", "grey", on))
    for i, av in enumerate(amap.avenues[:6], 1):
        star = _c("✦", "mag", on) if av.llm_written else " "
        head = _c(av.name, _IMPACT_COLOR[av.best_impact], on)
        L.append(f"  {star} {i}. {head}  " +
                 _c(f"→ {av.objective}  [{av.score}]", "grey", on))
        if av.narrative:
            L.append(_c(f"       {av.narrative}", "white", on))
    L.append("")

    # chains from the LLM, if any
    if synth and synth.get("chains"):
        L.append(b("  HYPOTHESISED CHAINS") + _c("  (LLM, unverified)", "grey", on))
        by_id = {l.fingerprint: l for l in amap.leads}
        for ch in synth["chains"][:4]:
            L.append(_c(f"  ✦ {ch['hypothesis']}", "mag", on))
            path = "  →  ".join(by_id[s].asset_key for s in ch["steps"] if s in by_id)
            L.append(_c(f"       {path}", "white", on))
            if ch.get("rationale"):
                L.append(_c(f"       {ch['rationale']}", "grey", on))
        L.append("")

    # top leads table
    L.append(b(f"  TOP LEADS") + _c(f"  (of {len(amap.leads)})", "grey", on))
    for lead in amap.leads[:top]:
        color = _IMPACT_COLOR[lead.impact]
        tag = _c(f"{lead.tag:<16}", color, on)
        pr = _c(f"{lead.priority:>5.1f}", "grey", on)
        L.append(f"  {pr}  {tag} {b(lead.title)}")
        L.append(_c(f"         {lead.asset_key}", "grey", on) +
                 (_c(f"  · {','.join(lead.refs)}", "amber", on) if lead.refs else ""))
        if lead.move:
            L.append(_c(f"         ↳ {lead.move}", "white", on))
    L.append("")

    if synth and synth.get("summary"):
        L.append(b("  SCOUT'S SUMMARY") +
                 _c(f"  ({synth.get('model','llm')})", "grey", on))
        for line in _wrap(synth["summary"], 64):
            L.append("  " + _c(line, "white", on))
        L.append("")
    return "\n".join(L)


def _wrap(text: str, width: int) -> list[str]:
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


# --- NDJSON (one lead per line, for piping) --------------------------------
def render_ndjson(amap: AttackMap) -> str:
    lines = []
    for lead in amap.leads:
        lines.append(json.dumps({
            "type": "lead",
            "target": amap.target,
            "zone": lead.zone.value,
            "title": lead.title,
            "asset": lead.asset_key,
            "impact": lead.impact.label,
            "exploitability": lead.exploitability.label,
            "priority": lead.priority,
            "move": lead.move,
            "detail": lead.detail,
            "confidence": lead.confidence.value,
            "source": lead.source_tool,
            "refs": lead.refs,
            "fingerprint": lead.fingerprint,
        }, default=str))
    return "\n".join(lines)


def render_json(amap: AttackMap, *, mode: str, sources: list[str],
                synth: dict | None = None, drift: dict | None = None) -> str:
    payload = {
        "target": amap.target,
        "knowledge": amap.knowledge,
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "headline": amap.headline,
        "stats": amap.graph.stats(),
        "impact_tally": amap.leads_by_impact(),
        "avenues": [{
            "name": a.name, "entry_zone": a.entry_zone.value,
            "objective": a.objective, "score": a.score,
            "llm_written": a.llm_written, "narrative": a.narrative,
            "leads": [l.fingerprint for l in a.leads],
        } for a in amap.avenues],
        "leads": [{
            "zone": l.zone.value, "title": l.title, "asset": l.asset_key,
            "impact": l.impact.label, "exploitability": l.exploitability.label,
            "priority": l.priority, "move": l.move, "detail": l.detail,
            "confidence": l.confidence.value, "source": l.source_tool,
            "refs": l.refs, "fingerprint": l.fingerprint,
        } for l in amap.leads],
        "llm_synthesis": synth or {},
        "drift": drift or {},
        "assets": [{
            "kind": a.kind.value, "key": a.key, "attrs": a.attrs,
            "sources": sorted(a.sources), "confidence": a.confidence.value,
            "cluster": a.cluster, "anomaly_score": a.anomaly_score,
        } for a in amap.graph.assets.values()],
    }
    return json.dumps(payload, indent=2, default=str)


# --- HTML fort plan (shareable artifact) -----------------------------------
IMPACT_HEX = {
    Impact.RCE: "#c65b4e", Impact.TAKEOVER: "#c65b4e",
    Impact.CREDENTIALS: "#cf9648", Impact.FOOTHOLD: "#cf9648",
    Impact.DATA: "#6f97c4", Impact.RECON: "#7d8ba0",
}


def _polar(cx, cy, r, a):
    return cx + r * math.cos(a), cy + r * math.sin(a)


def _zone_impact(amap: AttackMap, zone: Zone) -> Impact:
    leads = amap.zones[zone].leads
    return max((l.impact for l in leads), default=Impact.RECON)


def _fort_plan(amap: AttackMap) -> str:
    W, H = 840, 760
    cx, cy = 420.0, 370.0
    rb, proj = 176.0, 34.0
    n = len(PLAN_ZONES)
    parts = []
    # Vertices sit at the MIDPOINT of each zone's wall segment, so a zone owns a
    # full curtain between two projecting bastions (a proper star-fort trace).
    seg = 2 * math.pi / n
    corners = [_polar(cx, cy, rb, -math.pi / 2 + seg * (i - 0.5)) for i in range(n)]

    def out(p, d):
        dx, dy = p[0] - cx, p[1] - cy
        m = math.hypot(dx, dy) or 1
        return (p[0] + dx / m * d, p[1] + dy / m * d)

    # Arrowhead bastions jutting out at each corner.
    tips = [out(c, proj) for c in corners]

    r_moat = rb + proj + 30
    parts.append(f'<circle class="moat" cx="{cx}" cy="{cy}" r="{r_moat:.0f}"/>')

    for i, zone in enumerate(PLAN_ZONES):
        zv = amap.zones[zone]
        impact = _zone_impact(amap, zone)
        colour = IMPACT_HEX[impact] if zv.leads else "#39404d"
        c0, c1 = corners[i], corners[(i + 1) % n]
        t0, t1 = tips[i], tips[(i + 1) % n]
        # curtain c0->c1, with the two flanking bastion tips drawn as spurs.
        d = (f"M{t0[0]:.1f} {t0[1]:.1f} L{c0[0]:.1f} {c0[1]:.1f} "
             f"L{c1[0]:.1f} {c1[1]:.1f} L{t1[0]:.1f} {t1[1]:.1f}")
        opening = min(1.0, max(l.priority for l in zv.leads) / 20.0) if zv.leads else 0
        gap = opening * 20.0
        dash = "" if gap < 1.2 else f' stroke-dasharray="{max(6,26-gap):.0f} {gap:.0f}"'
        parts.append(f'<path class="wall" d="{d}" stroke="{colour}"{dash}/>')

        # Label at the zone's mid-angle, pushed well clear of the moat.
        a = -math.pi / 2 + seg * i
        lx, ly = _polar(cx, cy, r_moat + 46, a)
        anc = "middle"
        if math.cos(a) > 0.3:
            anc, lx = "start", lx + 6
        elif math.cos(a) < -0.3:
            anc, lx = "end", lx - 6
        dy = 0 if abs(math.sin(a)) < 0.5 else (-10 if math.sin(a) < 0 else 18)
        parts.append(f'<text class="zl" x="{lx:.0f}" y="{ly+dy:.0f}" '
                     f'text-anchor="{anc}">{_html.escape(ZONE_LABEL[zone])}</text>')
        n_leads = len(zv.leads)
        parts.append(f'<text class="zc" x="{lx:.0f}" y="{ly+dy+15:.0f}" '
                     f'text-anchor="{anc}">{n_leads} lead'
                     f'{"" if n_leads==1 else "s"} · {impact.label}</text>')

    # assault arrows: one per top avenue, pointing inward at its entry zone
    for rank, av in enumerate(amap.avenues[:4]):
        if av.entry_zone not in PLAN_ZONES:
            continue
        i = PLAN_ZONES.index(av.entry_zone)
        a = -math.pi / 2 + seg * i
        x1, y1 = _polar(cx, cy, r_moat + 78, a)
        x2, y2 = _polar(cx, cy, rb + 4, a)
        parts.append(f'<line class="assault" x1="{x1:.0f}" y1="{y1:.0f}" '
                     f'x2="{x2:.0f}" y2="{y2:.0f}"/>')
        ang = a + math.pi
        for da in (-0.42, 0.42):
            ex, ey = x2 + 12 * math.cos(ang + da), y2 + 12 * math.sin(ang + da)
            parts.append(f'<line class="assault" x1="{x2:.0f}" y1="{y2:.0f}" '
                         f'x2="{ex:.0f}" y2="{ey:.0f}"/>')

    keep = amap.zones[Zone.KEEP]
    ki = _zone_impact(amap, Zone.KEEP)
    kc = IMPACT_HEX[ki] if keep.leads else "#3a4657"
    kr = 50
    kpts = [_polar(cx, cy, kr, -math.pi/2 + 2*math.pi*i/6) for i in range(6)]
    parts.append('<path d="M' + " L".join(f"{x:.0f} {y:.0f}" for x,y in kpts)
                 + f' Z" fill="rgba(255,255,255,.03)" stroke="{kc}" stroke-width="2"/>')
    parts.append(f'<text class="kn" x="{cx:.0f}" y="{cy-2:.0f}" '
                 f'text-anchor="middle">THE KEEP</text>')
    parts.append(f'<text class="zc" x="{cx:.0f}" y="{cy+14:.0f}" '
                 f'text-anchor="middle">the objective</text>')

    return (f'<svg class="plan" viewBox="0 0 {W} {H}" role="img" '
            f'aria-label="Attack map of {_html.escape(amap.target)}">'
            + "".join(parts) + "</svg>")


CSS = """
:root{--bg:#12161d;--panel:#0d1117;--line:#2a3340;--ink:#d4d9e0;--dim:#8592a3;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Spectral",Georgia,serif;line-height:1.6}
.sheet{max-width:1140px;margin:0 auto;padding:52px 26px 90px}
.eyebrow{font-family:"JetBrains Mono",monospace;font-size:11px;letter-spacing:.22em;
text-transform:uppercase;color:var(--dim);margin:0 0 12px}
h1{font-family:"Bodoni Moda",Didot,serif;font-weight:500;font-size:clamp(34px,6vw,60px);
margin:0 0 8px;letter-spacing:-.015em}
h1 .q{display:block;font-size:.4em;font-style:italic;color:var(--dim);margin-top:12px;font-weight:400}
.meta{font-family:"JetBrains Mono",monospace;font-size:12px;color:var(--dim);
display:flex;flex-wrap:wrap;gap:6px 26px;margin-top:18px}
h2{font-family:"Bodoni Moda",Didot,serif;font-weight:500;font-size:27px;margin:0 0 6px}
.section{margin-top:64px}
.note{color:var(--dim);font-style:italic;font-size:14px;margin:0 0 22px;max-width:64ch}
.top{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:40px;
align-items:start;margin-top:38px}
.plan{width:100%;height:auto}
.plan .wall{fill:none;stroke-width:3.5;stroke-linejoin:miter}
.plan .moat{fill:none;stroke:#2a3340;stroke-width:1.3;stroke-dasharray:2 7;opacity:.6}
.plan .assault{stroke:#c65b4e;stroke-width:2;opacity:.9}
.plan text{font-family:"JetBrains Mono",monospace;fill:var(--ink)}
.plan .zl{font-size:11.5px;letter-spacing:.08em;text-transform:uppercase}
.plan .zc{font-size:10px;fill:var(--dim)}
.plan .kn{font-size:10px;letter-spacing:.16em;fill:var(--dim)}
.verdict{border:1px solid var(--line);background:var(--panel);padding:26px}
.headline{font-size:17px;margin:0 0 18px}
.tally{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
.tally li{display:flex;justify-content:space-between;padding:8px 0;
border-bottom:1px solid rgba(42,51,64,.5);font-family:"JetBrains Mono",monospace;font-size:12.5px}
.av{border-left:3px solid var(--line);padding:2px 0 2px 20px;margin:0 0 22px}
.av h3{font-family:"Spectral",serif;font-size:17px;margin:0 0 5px}
.av .obj{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.12em;
text-transform:uppercase;color:var(--dim);margin-bottom:6px}
.av p{margin:0;color:var(--dim);font-size:14px}
.av.llm{border-left-color:#b07cc6}
.lead{display:grid;grid-template-columns:64px 1fr;gap:14px;padding:14px 0;
border-bottom:1px solid rgba(42,51,64,.45)}
.pri{font-family:"JetBrains Mono",monospace;font-size:20px;text-align:right;color:var(--dim)}
.lead h4{font-family:"Spectral",serif;font-size:16px;font-weight:600;margin:0 0 4px}
.tags{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.08em;
text-transform:uppercase;color:var(--dim);margin-bottom:6px;display:flex;gap:14px;flex-wrap:wrap}
.lead .asset{font-family:"JetBrains Mono",monospace;font-size:12px;color:var(--ink)}
.move{color:var(--dim);font-size:13.5px;margin-top:6px}
.move::before{content:"↳ ";color:#7d8ba0}
.refs{font-family:"JetBrains Mono",monospace;font-size:11px;color:#cf9648}
.summary{border:1px solid #4a3a5c;background:rgba(176,124,198,.06);padding:22px;
font-size:15px}
.foot{margin-top:72px;padding-top:22px;border-top:1px solid var(--line);
font-family:"JetBrains Mono",monospace;font-size:11px;color:var(--dim);line-height:1.9}
@media(max-width:840px){.top{grid-template-columns:1fr}}
"""


def render_html(amap: AttackMap, *, mode: str, sources: list[str],
                synth: dict | None = None, elapsed: float = 0.0) -> str:
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    stats = amap.graph.stats()
    tally = "".join(f'<li><span>{k}</span><span>{v}</span></li>'
                    for k, v in amap.leads_by_impact().items() if v)

    avenues = []
    for i, av in enumerate(amap.avenues[:8], 1):
        cls = "av llm" if av.llm_written else "av"
        avenues.append(
            f'<div class="{cls}"><div class="obj">{i} · route to '
            f'{_html.escape(av.objective)} · score {av.score}'
            f'{" · ✦ synthesised" if av.llm_written else ""}</div>'
            f'<h3>{_html.escape(av.name)}</h3>'
            f'<p>{_html.escape(av.narrative)}</p></div>')

    leads = []
    for l in amap.leads[:60]:
        refs = (f'<span class="refs">{_html.escape(", ".join(l.refs))}</span>'
                if l.refs else "")
        leads.append(
            f'<div class="lead"><div class="pri">{l.priority:.0f}</div><div>'
            f'<div class="tags"><span>{_html.escape(l.tag)}</span>'
            f'<span>{_html.escape(ZONE_LABEL[l.zone])}</span>'
            f'<span>{l.confidence.value}</span>{refs}</div>'
            f'<h4>{_html.escape(l.title)}</h4>'
            f'<div class="asset">{_html.escape(l.asset_key[:80])}</div>'
            f'{f"<div class=move>{_html.escape(l.move)}</div>" if l.move else ""}'
            f'</div></div>')

    summary = ""
    if synth and synth.get("summary"):
        summary = (f'<section class="section"><h2>Scout\'s summary</h2>'
                   f'<div class="summary">{_html.escape(synth["summary"])}'
                   f'<div class="note" style="margin-top:12px">Synthesised by '
                   f'{_html.escape(synth.get("model","local model"))}; grounded '
                   f'in the leads above.</div></div></section>')

    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bastion — {_html.escape(amap.target)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bodoni+Moda:opsz,wght@6..96,400;6..96,500&family=Spectral:ital,wght@0,400;0,600;1,400&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body><div class="sheet">
<p class="eyebrow">Bastion · scout's report · {mode} · {amap.knowledge}-box</p>
<h1>{_html.escape(amap.target)}<span class="q">The works, the weak points, and the way in</span></h1>
<div class="meta"><span>{now}</span>
<span>{stats.get('host',0)} names · {stats.get('live_hosts',0)} live</span>
<span>{stats.get('ip',0)} addresses · {stats.get('service',0)} services</span>
<span>{len(amap.leads)} leads</span><span>{elapsed:.1f}s</span></div>
<section class="top">{_fort_plan(amap)}
<div class="verdict"><p class="headline">{_html.escape(amap.headline)}</p>
<ul class="tally">{tally}</ul></div></section>
<section class="section"><h2>Avenues of approach</h2>
<p class="note">Ranked routes in. Wall colour on the plan is the best impact
reachable at each zone; breaches mark where the wall is open; arrows are the
assault routes below. ✦ marks routes the local model proposed.</p>
{"".join(avenues)}</section>
{summary}
<section class="section"><h2>Leads</h2>
<p class="note">Ranked by impact × exploitability. Every lead carries the next
move and a confidence — passive intel is often stale, and a reported lead is a
lead, not a fact.</p>{"".join(leads)}</section>
<footer class="foot"><div>Sources: {_html.escape(", ".join(sources)) or "none"}</div>
<div>{mode} · {amap.knowledge}-box. Authorised engagement use only.</div></footer>
</div></body></html>"""
