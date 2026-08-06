#!/usr/bin/env python3
"""
claude_token_audit.py -- local token/cost audit for Claude usage.

Zero dependencies. Python 3.9+. Standard library only.
Nothing leaves your machine. No network calls.

TWO INPUT MODES (auto-detected):

  1. claude.ai data export
     Settings > Privacy > Export data -> emailed ZIP -> conversations.json
     Token counts are ESTIMATED (no real counts exist in the export).

  2. Claude Code session logs
     ~/.claude/projects/**/*.jsonl
     Token counts are REAL (read from the usage field on each API response).

USAGE
  python3 claude_token_audit.py conversations.json
  python3 claude_token_audit.py ~/.claude/projects
  python3 claude_token_audit.py conversations.json ~/.claude/projects -o report.html

Output: a self-contained HTML report with inline SVG charts.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import chatexport
import analysis

# --------------------------------------------------------------------------
# Estimation constants -- edit these to match your situation.
# --------------------------------------------------------------------------

CHARS_PER_TOKEN = 3.8  # English + code mix. Pure code trends lower (~3.2).

# USD per million tokens. Verify against current pricing before trusting the
# dollar figures; these are here so the relative ranking is meaningful.
PRICE_PER_MTOK = {
    "opus":   {"in": 15.00, "out": 75.00, "cache_write": 18.75, "cache_read": 1.50},
    "sonnet": {"in":  3.00, "out": 15.00, "cache_write":  3.75, "cache_read": 0.30},
    "haiku":  {"in":  0.80, "out":  4.00, "cache_write":  1.00, "cache_read": 0.08},
}
DEFAULT_FAMILY = "sonnet"


def family_of(model_name):
    m = (model_name or "").lower()
    for fam in ("opus", "sonnet", "haiku"):
        if fam in m:
            return fam
    return DEFAULT_FAMILY


def est_tokens(text):
    if not text:
        return 0
    return int(len(text) / CHARS_PER_TOKEN)


def parse_ts(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OSError):
            return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
        if not m:
            return None
        try:
            dt = datetime.fromisoformat(m.group(1))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def flatten_content(content):
    """Pull plain text out of the several shapes message content can take."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        for key in ("text", "content", "input", "thinking"):
            if key in content:
                return flatten_content(content[key])
        return json.dumps(content)
    if isinstance(content, list):
        return "\n".join(flatten_content(c) for c in content)
    return str(content)


# --------------------------------------------------------------------------
# Mode 1: claude.ai conversation export
# --------------------------------------------------------------------------

def analyze_chat_export(path):
    """Token spend per conversation from a claude.ai export.

    The critical modelling point: every turn re-sends the whole conversation
    so far. A conversation's true cost is not the sum of its message lengths,
    it is the sum over turns of the running prefix. That is quadratic in turn
    count, which is why long threads dominate a bill.

    Counts come from the exact_count.py sidecar where available and fall back
    to character estimation otherwise. Coverage is tracked per conversation so
    the report never presents a mostly-estimated thread as measured.
    """
    sidecar = chatexport.read_sidecar(path) or {}
    if sidecar:
        print(f"  sidecar found: {len(sidecar):,} conversations")

    convos = []
    for key, name, conv, turn_data in chatexport.load(path):
        measured = sidecar.get(key) or {}

        # Per-turn vector retained for the insight layer (analysis.py):
        # (role, tokens, attachment_tokens). attachment_tokens is the share of
        # this message's tokens attributable to attachments, allocated by the
        # attachment's character fraction -- always an estimate, even when the
        # message total is measured.
        turns = []
        texts = []
        n_measured = 0
        for index, role, text, attach_chars in turn_data:
            hit = measured.get(str(index))
            if hit is not None:
                tok = int(hit)
                n_measured += 1
            else:
                tok = est_tokens(text)
            attach_tok = 0
            if attach_chars and text:
                attach_tok = int(tok * min(attach_chars, len(text)) / len(text))
            turns.append((role, tok, attach_tok))
            texts.append(text)

        written_in = sum(t for s, t, _a in turns if s in ("human", "user"))
        written_out = sum(t for s, t, _a in turns if s not in ("human", "user"))

        # Billable context: prefix re-sent on every assistant response.
        prefix = 0
        billable_in = 0
        for role, tok, _a in turns:
            if role in ("human", "user"):
                prefix += tok
                billable_in += prefix
            else:
                prefix += tok

        convos.append({
            "key": key,
            "name": name,
            "created": parse_ts(conv.get("created_at") or conv.get("create_time")),
            "updated": parse_ts(conv.get("updated_at") or conv.get("update_time")),
            "turns": len(turns),
            "coverage": n_measured / len(turns) if turns else 0.0,
            "written_in": written_in,
            "written_out": written_out,
            "billable_in": billable_in,
            "total": billable_in + written_out,
            "turns_tok": turns,
            "turns_text": texts,
        })

    convos.sort(key=lambda c: c["total"], reverse=True)
    return convos


# --------------------------------------------------------------------------
# Mode 2: Claude Code session logs (real token counts)
# --------------------------------------------------------------------------

USAGE_KEYS = {
    "input_tokens": "in",
    "output_tokens": "out",
    "cache_creation_input_tokens": "cache_write",
    "cache_read_input_tokens": "cache_read",
}


def blank_bucket():
    return {"in": 0, "out": 0, "cache_write": 0, "cache_read": 0,
            "calls": 0, "models": defaultdict(int)}


def find_usage(obj):
    """Depth-first search for usage dicts; log schemas shift between versions."""
    found = []
    if isinstance(obj, dict):
        if any(k in obj for k in USAGE_KEYS):
            found.append(obj)
        for value in obj.values():
            found.extend(find_usage(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(find_usage(item))
    return found


def analyze_code_logs(root):
    root = Path(root).expanduser()
    files = sorted(root.rglob("*.jsonl")) if root.is_dir() else [root]

    sessions = defaultdict(blank_bucket)
    projects = defaultdict(blank_bucket)
    daily = defaultdict(blank_bucket)
    models = defaultdict(blank_bucket)
    tools = defaultdict(int)
    skipped = 0

    for fp in files:
        project = fp.parent.name
        session_id = f"{project}/{fp.stem}"
        try:
            handle = fp.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                for name in re.findall(r'"name"\s*:\s*"(\w+)"', line):
                    if name in ("Bash", "Read", "Edit", "Write", "Grep",
                                "Glob", "Task", "WebFetch", "WebSearch"):
                        tools[name] += 1

                msg = rec.get("message") if isinstance(rec, dict) else None
                model = (msg or {}).get("model") if isinstance(msg, dict) else None
                model = model or (rec.get("model") if isinstance(rec, dict) else None)
                day = parse_ts((rec or {}).get("timestamp"))
                day_key = day.strftime("%Y-%m-%d") if day else "unknown"

                for usage in find_usage(rec):
                    counts = {v: int(usage.get(k) or 0)
                              for k, v in USAGE_KEYS.items()}
                    if not any(counts.values()):
                        continue
                    for bucket, key in ((sessions, session_id),
                                        (projects, project),
                                        (daily, day_key),
                                        (models, model or "unknown")):
                        target = bucket[key]
                        for field, val in counts.items():
                            target[field] += val
                        target["calls"] += 1
                        if model:
                            target["models"][model] += 1

    return {"sessions": dict(sessions), "projects": dict(projects),
            "daily": dict(daily), "models": dict(models),
            "tools": dict(tools), "files": len(files), "skipped": skipped}


def cost_of(bucket, model_hint=None):
    fam = family_of(model_hint or
                    (max(bucket["models"], key=bucket["models"].get)
                     if bucket.get("models") else None))
    p = PRICE_PER_MTOK[fam]
    return (bucket["in"] * p["in"]
            + bucket["out"] * p["out"]
            + bucket["cache_write"] * p["cache_write"]
            + bucket["cache_read"] * p["cache_read"]) / 1_000_000


# --------------------------------------------------------------------------
# Inline SVG charts -- no CDN, no JS, renders in any browser
# --------------------------------------------------------------------------

# Palette: instrument panel, not dashboard-dark. Deep slate ground rather
# than black, amber for consumption (a gauge reading, not a brand colour),
# and a cool slate-blue reserved exclusively for the measured/estimated
# distinction so provenance is legible at a glance.
BG        = "#0e1216"
SURFACE   = "#161c23"
SURFACE_2 = "#1d242d"
LINE      = "#2a333e"
INK       = "#dfe5ec"
MUTED     = "#7d8b9c"
ACCENT    = "#e0a458"   # consumption
ACCENT_DIM= "#8a6538"
COOL      = "#5d9bb8"   # reference / measured
WARN      = "#cf6a55"   # overhead, waste


def hatch_defs():
    """Diagonal hatch marks estimated data. Solid fill means measured.

    This is the one piece of visual encoding that carries meaning rather
    than decoration: you can tell at a glance which bars you can trust.
    """
    return (
        '<defs>'
        '<pattern id="est" width="6" height="6" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)">'
        f'<rect width="6" height="6" fill="{ACCENT_DIM}" opacity="0.35"/>'
        f'<line x1="0" y1="0" x2="0" y2="6" stroke="{ACCENT}" '
        'stroke-width="2.5" opacity="0.75"/>'
        '</pattern></defs>')


def bar_chart(rows, title, width=760, row_h=30, fmt=lambda v: f"{v:,.0f}"):
    """rows: (label, value) or (label, value, measured_bool)."""
    if not rows:
        return f"<p class='empty'>No data for {escape(title)}.</p>"
    rows = [(r[0], r[1], r[2] if len(r) > 2 else None) for r in rows]
    label_w = 250
    peak = max(v for _, v, _ in rows) or 1
    height = row_h * len(rows) + 20
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{escape(title)}" class="chart">', hatch_defs()]
    for i, (label, value, measured) in enumerate(rows):
        y = i * row_h + 10
        bar_w = max(1, (value / peak) * (width - label_w - 110))
        short = label if len(label) <= 34 else label[:33] + "\u2026"
        fill = "url(#est)" if measured is False else ACCENT
        out.append(
            f'<text x="0" y="{y + 14}" class="lbl">{escape(short)}</text>'
            f'<rect x="{label_w}" y="{y + 3}" width="{bar_w:.1f}" height="16" '
            f'rx="2" fill="{fill}"/>'
            f'<text x="{label_w + bar_w + 8:.1f}" y="{y + 15}" class="val">'
            f'{escape(fmt(value))}</text>')
    out.append("</svg>")
    return "".join(out)


def line_chart(pairs, title, width=760, height=220):
    if len(pairs) < 2:
        return f"<p class='empty'>Not enough points for {escape(title)}.</p>"
    peak = max(v for _, v in pairs) or 1
    pad_l, pad_b, pad_t = 60, 34, 12
    plot_w = width - pad_l - 16
    plot_h = height - pad_b - pad_t
    step = plot_w / (len(pairs) - 1)
    pts = [(pad_l + i * step, pad_t + plot_h - (v / peak) * plot_h)
           for i, (_, v) in enumerate(pairs)]
    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}"
                    for i, (x, y) in enumerate(pts))
    area = (f"M{pts[0][0]:.1f},{pad_t + plot_h} "
            + " ".join(f"L{x:.1f},{y:.1f}" for x, y in pts)
            + f" L{pts[-1][0]:.1f},{pad_t + plot_h} Z")
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{escape(title)}" class="chart">',
           f'<defs><linearGradient id="fade" x1="0" x2="0" y1="0" y2="1">'
           f'<stop offset="0%" stop-color="{ACCENT}" stop-opacity="0.28"/>'
           f'<stop offset="100%" stop-color="{ACCENT}" stop-opacity="0"/>'
           f'</linearGradient></defs>']
    for frac in (0, 0.5, 1):
        y = pad_t + plot_h - frac * plot_h
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - 16}" '
                   f'y2="{y:.1f}" stroke="{LINE}"/>'
                   f'<text x="0" y="{y + 4:.1f}" class="val">'
                   f'{peak * frac / 1000:,.0f}k</text>')
    out.append(f'<path d="{area}" fill="url(#fade)"/>')
    out.append(f'<path d="{path}" fill="none" stroke="{ACCENT}" '
               f'stroke-width="1.75" stroke-linejoin="round"/>')
    stride = max(1, len(pairs) // 8)
    for i in range(0, len(pairs), stride):
        out.append(f'<circle cx="{pts[i][0]:.1f}" cy="{pts[i][1]:.1f}" r="2.5" '
                   f'fill="{BG}" stroke="{ACCENT}" stroke-width="1.5"/>')
        out.append(f'<text x="{pts[i][0]:.1f}" y="{height - 10}" '
                   f'class="val" text-anchor="middle">'
                   f'{escape(str(pairs[i][0])[-5:])}</text>')
    out.append("</svg>")
    return "".join(out)


CSS = f"""
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:44px 20px 96px; background:{BG}; color:{INK};
  font:15px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased; }}
main {{ max-width:880px; margin:0 auto; }}

h1 {{ font-size:15px; font-weight:600; letter-spacing:.16em;
  text-transform:uppercase; margin:0 0 6px; color:{INK}; }}
.sub {{ color:{MUTED}; margin:0 0 40px; font-size:13px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
h2 {{ font-size:11px; text-transform:uppercase; letter-spacing:.14em;
  color:{MUTED}; margin:52px 0 16px; font-weight:600;
  padding-bottom:8px; border-bottom:1px solid {LINE}; }}

.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(148px,1fr));
  gap:10px; }}
.card {{ background:{SURFACE}; border:1px solid {LINE}; border-radius:6px;
  padding:16px 18px; }}
.card b {{ display:block; font-size:27px; letter-spacing:-.02em;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-weight:500; color:{ACCENT}; line-height:1.15; }}
.card.warn {{ border-color:{WARN}44; }}
.card.warn b {{ color:{WARN}; }}
.card span {{ font-size:10.5px; color:{MUTED}; text-transform:uppercase;
  letter-spacing:.1em; display:block; margin-top:6px; }}

.chart {{ width:100%; height:auto; background:{SURFACE}; border:1px solid {LINE};
  border-radius:6px; padding:16px; margin-bottom:8px; }}
.lbl {{ font:12px ui-sans-serif,sans-serif; fill:{INK}; }}
.val {{ font:10.5px ui-monospace,SFMono-Regular,Menlo,monospace; fill:{MUTED}; }}

.note {{ background:{SURFACE}; border-left:2px solid {COOL};
  padding:13px 17px; border-radius:0 6px 6px 0; font-size:13.5px;
  color:#aab6c4; margin:16px 0; }}
.note b {{ color:{INK}; font-weight:600; }}
.note code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12.5px; background:{SURFACE_2}; padding:1px 5px;
  border-radius:3px; color:{COOL}; }}
.empty {{ color:{MUTED}; font-style:italic; }}

.callout {{ background:linear-gradient(180deg,{SURFACE_2},{SURFACE});
  border:1px solid {ACCENT}55; border-left:3px solid {ACCENT};
  border-radius:8px; padding:18px 20px; margin:16px 0; font-size:15px;
  line-height:1.6; color:{INK}; }}
.callout b {{ color:{ACCENT}; font-weight:600; }}

.steps {{ background:{SURFACE}; border:1px solid {LINE}; border-radius:8px;
  padding:16px 20px 16px; margin:16px 0; font-size:14px; color:#aab6c4; }}
.steps > b {{ color:{INK}; font-size:11px; text-transform:uppercase;
  letter-spacing:.12em; display:block; margin-bottom:10px; }}
.steps ol {{ margin:0; padding-left:20px; }}
.steps li {{ margin:6px 0; line-height:1.55; }}
.steps b {{ color:{INK}; font-weight:600; }}

.key {{ display:flex; gap:20px; align-items:center; margin:10px 0 0;
  font-size:11px; color:{MUTED}; text-transform:uppercase;
  letter-spacing:.09em; }}
.key i {{ display:inline-block; width:22px; height:10px; border-radius:2px;
  margin-right:7px; vertical-align:middle; background:{ACCENT}; }}
.key i.est {{ background:repeating-linear-gradient(45deg,
  {ACCENT} 0 2px, {ACCENT_DIM} 2px 5px); }}

.tw {{ overflow-x:auto; -webkit-overflow-scrolling:touch; }}
table {{ width:100%; min-width:520px; border-collapse:collapse; font-size:13px;
  background:{SURFACE}; border:1px solid {LINE}; border-radius:6px;
  overflow:hidden; }}
th,td {{ padding:9px 13px; text-align:left;
  border-bottom:1px solid {LINE}; }}
th {{ font-size:10px; text-transform:uppercase; letter-spacing:.1em;
  color:{MUTED}; font-weight:600; background:{SURFACE_2}; }}
td.n {{ text-align:right;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:{INK}; }}
tbody tr:hover td {{ background:{SURFACE_2}; }}
tr:last-child td {{ border-bottom:none; }}
td.src {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.08em;
  color:{MUTED}; }}
td.src.m {{ color:{COOL}; }}

@media (max-width:640px) {{
  body {{ padding:28px 14px 64px; }}
  .card b {{ font-size:22px; }}
  table {{ font-size:12px; }}
  th,td {{ padding:7px 9px; }}
}}
"""



def provenance(conv):
    cov = conv.get("coverage", 0.0)
    if cov >= 0.99:
        return "measured"
    if cov <= 0:
        return "estimated"
    return f"{cov * 100:.0f}% measured"


def _tok(n):
    """Compact token label: 412k, 1.2M."""
    n = float(n)
    if abs(n) >= 1e6:
        return f"{n / 1e6:,.1f}M"
    if abs(n) >= 1e3:
        return f"{n / 1e3:,.0f}k"
    return f"{n:,.0f}"


def render_findings(chat):
    """The v0.3 insight layer: plain-language optimization findings.

    Pure presentation. All numbers come from analysis.py (arithmetic only);
    this function decides nothing, it only phrases what was found and tags each
    figure measured/estimated so an estimate is never dressed up as a measure.
    """
    af = analysis.account_findings(chat)
    per_conv = af["per_conversation"]
    if not per_conv:
        return ""

    h = ["<h2>Optimization findings</h2>",
         "<div class='note'>Arithmetic only &mdash; no model judged your "
         "chats. Each figure below is tagged <b>measured</b> or "
         "<b>estimated</b> depending on whether that conversation was counted "
         "exactly. Attachment shares are always approximate (allocated by "
         "character fraction).</div>"]

    # Headline callout: the single heaviest conversation, phrased for a human.
    top = per_conv[0]
    prov = "measured" if top["coverage"] >= 0.99 else "estimated"
    overhead_pct = ((top["total"] - top["written"]) / max(top["total"], 1)) * 100
    parts = [f"<b>{escape(top['name'][:70])}</b> cost "
             f"<b>{_tok(top['total'])}</b> tokens ({prov}). "
             f"{overhead_pct:.0f}% of that was re-sent context, not new text — "
             "every message you send quietly re-sends the whole thread so far."]
    fu = top["first_user_message"]
    if fu and fu["times_paid"] > 1:
        parts.append(f"Your opening message alone was re-sent (and paid for) "
                     f"<b>{fu['times_paid']} times</b>.")
    sp = top["split"]
    if sp:
        where = (f"your <b>{escape(analysis.ordinal_label(sp['message_no']))} "
                 "message</b>" if sp.get("message_no")
                 else f"turn <b>{sp['turn']}</b>")
        line = (f"The fix: if you had started a <b>new chat</b> right after "
                f"{where}")
        if sp.get("quote"):
            line += f" (the one that begins &ldquo;{escape(sp['quote'])}&rdquo;)"
        line += (f" and pasted a short recap instead of continuing, you'd have "
                 f"saved ~<b>{_tok(sp['savings'])}</b> ({sp['pct']:.0f}%).")
        parts.append(line)
    h.append("<div class='callout'>" + " ".join(parts) + "</div>")

    # Plain-language, do-this-next steps (HTML report only).
    h.append(
        "<div class='steps'><b>How to act on this</b><ol>"
        "<li>When a chat gets long, <b>start a new one</b> instead of "
        "continuing the same thread.</li>"
        "<li>Carry over only a <b>short recap</b> &mdash; the goal plus any key "
        "facts or code &mdash; not the whole history.</li>"
        "<li>Avoid re-attaching large files; paste just the relevant part or "
        "its conclusion.</li>"
        "<li>Split the heavy threads at the message flagged in the "
        "<b>Start fresh after</b> column below.</li>"
        "<li>Keep one chat to one topic; branch a new topic into a new "
        "chat.</li></ol></div>")

    # Account-level rollups.
    cards = []
    if af["total_split_savings"] > 0:
        cards.append(
            f"<div class='card warn'><b>{_tok(af['total_split_savings'])}</b>"
            f"<span>saveable via {af['split_count']} split"
            f"{'s' if af['split_count'] != 1 else ''}</span></div>")
    if af["median_total"] > 0:
        cards.append(
            f"<div class='card'><b>{_tok(af['median_total'])}</b>"
            "<span>median conversation</span></div>")
    if af["spikes"]:
        cards.append(
            f"<div class='card warn'><b>{len(af['spikes'])}</b>"
            f"<span>spikes &gt;{af['spike_mult']:g}&times; median</span></div>")
    if cards:
        h.append("<div class='cards'>" + "".join(cards) + "</div>")

    if af["spikes"]:
        top_spike = af["spikes"][0]
        h.append(
            "<div class='note'><b>Spikes.</b> "
            f"{len(af['spikes'])} conversation"
            f"{'s' if len(af['spikes']) != 1 else ''} ran more than "
            f"{af['spike_mult']:g}&times; your median of "
            f"{_tok(af['median_total'])} tokens. Heaviest: "
            f"<b>{escape(top_spike['name'][:50])}</b> at "
            f"{top_spike['mult']:.1f}&times;.</div>")

    # Per-conversation recommendation table -- only rows with something to act on.
    actionable = [f for f in per_conv
                  if f["split"] or f["knee"] or f["attachment"]
                  or (f["first_user_message"]
                      and f["first_user_message"]["times_paid"] > 3)]
    if actionable:
        h.append("<div class='tw'><table><tr><th>Conversation</th>"
                 "<th class='n'>Turns</th><th class='n'>Billable</th>"
                 "<th class='n'>Opening&nbsp;msg re-sent</th>"
                 "<th>Start fresh after</th>"
                 "<th class='n'>Saves</th><th class='n'>Attach</th>"
                 "<th>Source</th></tr>")
        for f in actionable[:15]:
            fu = f["first_user_message"]
            times = f"{fu['times_paid']}&times;" if fu else "&mdash;"
            if f["split"]:
                start_after = (f"your {escape(analysis.ordinal_label(f['split']['message_no']))} "
                               "message" if f["split"].get("message_no")
                               else f"turn {f['split']['turn']}")
            else:
                start_after = "&mdash;"
            saves = _tok(f["split"]["savings"]) if f["split"] else "&mdash;"
            attach = (f"{f['attachment']['pct']:.0f}%"
                      if f["attachment"] else "&mdash;")
            meas = f["coverage"] >= 0.99
            h.append(
                f"<tr><td>{escape(f['name'][:52])}</td>"
                f"<td class='n'>{f['turns']}</td>"
                f"<td class='n'>{f['billable_in']:,}</td>"
                f"<td class='n'>{times}</td>"
                f"<td>{start_after}</td>"
                f"<td class='n'>{saves}</td>"
                f"<td class='n'>{attach}</td>"
                f"<td class='src{' m' if meas else ''}'>"
                f"{'measured' if meas else 'estimated'}</td></tr>")
        h.append("</table></div>")
        h.append("<p class='key'><span><b>Start fresh after</b> = open a new "
                 "chat once you're past this message &middot; <b>Saves</b> = "
                 "tokens that avoids &middot; <b>Opening msg re-sent</b> = how "
                 "many times your first message was re-paid</span></p>")

    return "".join(h)


def build_report(chat, code, out_path):
    h = [f"<!doctype html><meta charset='utf-8'>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>Claude token audit</title><style>{CSS}</style><main>",
         "<h1>Claude token audit</h1>",
         f"<p class='sub'>Generated {datetime.now():%d %b %Y, %H:%M} "
         f"&middot; all processing local</p>"]

    if chat:
        total = sum(c["total"] for c in chat)
        written = sum(c["written_in"] + c["written_out"] for c in chat)
        overhead = total - written
        turns_all = sum(c["turns"] for c in chat)
        turns_meas = sum(round(c["coverage"] * c["turns"]) for c in chat)
        pct = turns_meas / max(turns_all, 1) * 100
        full = sum(1 for c in chat if c["coverage"] >= 0.99)

        if pct >= 99:
            h.append("<h2>claude.ai conversations &mdash; measured</h2>")
            h.append("<div class='note'><b>Measured, not guessed.</b> Every "
                     "message was counted exactly via the free "
                     "<code>count_tokens</code> endpoint, at zero billable "
                     "cost.</div>")
        elif pct > 0:
            h.append("<h2>claude.ai conversations &mdash; partly measured</h2>")
            h.append(
                f"<div class='note'><b>Mixed provenance.</b> {pct:.1f}% of "
                f"messages were counted exactly; {full:,} of {len(chat):,} "
                "conversations are fully covered. The rest fall back to "
                "character estimation. Re-run <code>exact_count.py</code> to "
                "close the gap &mdash; cached messages are not re-counted."
                "</div>")
        else:
            h.append("<h2>claude.ai conversations &mdash; estimated</h2>")
            h.append(
                "<div class='note'><b>These are estimates.</b> The claude.ai "
                "export contains no token counts, so figures are derived from "
                f"character length at ~{CHARS_PER_TOKEN} chars/token. Run "
                "<code>exact_count.py</code> to replace these with measured "
                "counts at zero token cost.</div>")

        h.append("<div class='cards'>"
                 f"<div class='card'><b>{len(chat):,}</b>"
                 "<span>conversations</span></div>"
                 f"<div class='card'><b>{total / 1e6:,.1f}M</b>"
                 f"<span>{'est. ' if pct < 99 else ''}billable tokens</span>"
                 "</div>"
                 f"<div class='card warn'><b>{overhead / max(total, 1) * 100:.0f}%</b>"
                 "<span>from context re-send</span></div>"
                 f"<div class='card'><b>{sum(c['turns'] for c in chat):,}</b>"
                 "<span>total turns</span></div></div>")

        h.append(render_findings(chat))

        h.append("<h2>Heaviest conversations</h2>")
        h.append(bar_chart(
            [(c["name"], c["total"], c["coverage"] >= 0.99) for c in chat[:15]],
            "Heaviest conversations"))
        if 0 < pct < 100:
            h.append("<p class='key'><span><i></i>measured</span>"
                     "<span><i class='est'></i>estimated</span></p>")

        h.append("<h2>Context overhead vs. words actually written</h2>")
        h.append(
            "<div class='note'>Every turn re-sends the entire thread. A "
            "40-turn chat pays for its early messages 40 times over. The gap "
            "below is what long threads cost you beyond the text itself."
            "</div>")
        h.append(bar_chart(
            [("Text you and I actually wrote", written),
             ("Re-sent context (pure overhead)", overhead)],
            "Overhead split"))

        by_day = defaultdict(int)
        for c in chat:
            if c["created"]:
                by_day[c["created"].strftime("%Y-%m-%d")] += c["total"]
        if by_day:
            h.append(f"<h2>{'Estimated s' if pct < 99 else 'S'}pend "
                     "over time</h2>")
            h.append(line_chart(sorted(by_day.items())[-60:], "Daily estimate"))

        h.append("<h2>Detail</h2><div class='tw'><table><tr><th>Conversation</th>"
                 "<th class='n'>Turns</th><th class='n'>Written</th>"
                 "<th class='n'>Billable</th><th class='n'>Overhead</th><th>Source</th></tr>")
        for c in chat[:25]:
            written_c = c["written_in"] + c["written_out"]
            mult = c["total"] / max(written_c, 1)
            h.append(f"<tr><td>{escape(c['name'][:60])}</td>"
                     f"<td class='n'>{c['turns']}</td>"
                     f"<td class='n'>{written_c:,}</td>"
                     f"<td class='n'>{c['total']:,}</td>"
                     f"<td class='n'>{mult:.1f}&times;</td>"
                     f"<td class='src{' m' if c['coverage'] >= 0.99 else ''}'>"
                     f"{provenance(c)}</td></tr>")
        h.append("</table></div>")

    if code:
        tot = blank_bucket()
        for bucket in code["sessions"].values():
            for k in ("in", "out", "cache_write", "cache_read", "calls"):
                tot[k] += bucket[k]
        grand = tot["in"] + tot["out"] + tot["cache_write"] + tot["cache_read"]
        cached = tot["cache_read"] / max(tot["cache_read"] + tot["in"], 1) * 100
        cost = sum(cost_of(b) for b in code["models"].values())

        h.append("<h2>Claude Code &mdash; measured</h2>")
        h.append(f"<div class='note'>Real token counts from "
                 f"{code['files']} session log(s). Dollar figures use the "
                 f"rate table at the top of the script &mdash; check it "
                 f"against current pricing.</div>")
        h.append("<div class='cards'>"
                 f"<div class='card'><b>{grand / 1e6:,.1f}M</b>"
                 "<span>total tokens</span></div>"
                 f"<div class='card'><b>${cost:,.2f}</b>"
                 "<span>est. equivalent</span></div>"
                 f"<div class='card'><b>{cached:.0f}%</b>"
                 "<span>served from cache</span></div>"
                 f"<div class='card'><b>{tot['calls']:,}</b>"
                 "<span>API calls</span></div></div>")

        h.append("<h2>Tokens by project</h2>")
        proj = sorted(((k, v["in"] + v["out"] + v["cache_write"] + v["cache_read"])
                       for k, v in code["projects"].items()),
                      key=lambda x: -x[1])[:15]
        h.append(bar_chart(proj, "Tokens by project"))

        h.append("<h2>Heaviest sessions</h2>")
        def sess_label(key):
            proj, _, stem = key.rpartition("/")
            return f"{proj}  {stem[:8]}" if proj else stem[:8]

        sess = sorted(((sess_label(k),
                        v["in"] + v["out"] + v["cache_write"] + v["cache_read"])
                       for k, v in code["sessions"].items()),
                      key=lambda x: -x[1])[:15]
        h.append(bar_chart(sess, "Heaviest sessions"))

        h.append("<h2>Token type mix</h2>")
        h.append("<div class='note'>Cache reads are roughly a tenth the price "
                 "of fresh input. A low cache share on long sessions is the "
                 "single most actionable number here.</div>")
        h.append(bar_chart([("Fresh input", tot["in"]),
                            ("Cache read (cheap)", tot["cache_read"]),
                            ("Cache write", tot["cache_write"]),
                            ("Output (priciest)", tot["out"])],
                           "Token mix"))

        day_series = sorted((k, v["in"] + v["out"] + v["cache_write"] + v["cache_read"])
                            for k, v in code["daily"].items() if k != "unknown")
        if day_series:
            h.append("<h2>Daily volume</h2>")
            h.append(line_chart(day_series[-60:], "Daily tokens"))

        if code["models"]:
            h.append("<h2>Spend by model</h2>")
            h.append(bar_chart(
                sorted(((k, cost_of(v, k)) for k, v in code["models"].items()),
                       key=lambda x: -x[1]),
                "Cost by model", fmt=lambda v: f"${v:,.2f}"))

        if code["tools"]:
            h.append("<h2>Tool call frequency</h2>")
            h.append(bar_chart(
                sorted(code["tools"].items(), key=lambda x: -x[1])[:12],
                "Tool calls"))

    if not chat and not code:
        h.append("<p class='empty'>No usable data found in the given paths.</p>")

    h.append("</main>")
    Path(out_path).write_text("".join(h), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+",
                    help="conversations.json and/or ~/.claude/projects")
    ap.add_argument("-o", "--out", default="claude_token_audit.html")
    args = ap.parse_args()

    chat, code = None, None
    for raw in args.paths:
        p = Path(raw).expanduser()
        if not p.exists():
            print(f"  ! not found: {p}", file=sys.stderr)
            continue
        if p.is_dir() or p.suffix == ".jsonl":
            print(f"  reading session logs: {p}")
            code = analyze_code_logs(p)
        elif p.suffix == ".json":
            print(f"  reading chat export: {p}")
            chat = analyze_chat_export(p)
        else:
            print(f"  ! unrecognised: {p}", file=sys.stderr)

    build_report(chat, code, args.out)
    print(f"\n  wrote {args.out}  ({os.path.getsize(args.out):,} bytes)")
    print("  open it in any browser.")


if __name__ == "__main__":
    main()
