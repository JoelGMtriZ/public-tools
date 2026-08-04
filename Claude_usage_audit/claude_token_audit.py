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

def load_sidecar(path):
    """Measured counts from exact_count.py, if the user has run it."""
    side = Path(path).with_suffix(".tokens.json")
    if not side.exists():
        return None
    try:
        return json.loads(side.read_text(encoding="utf-8")).get("counts") or None
    except (json.JSONDecodeError, OSError):
        return None


def analyze_chat_export(path):
    """Token spend per conversation from a claude.ai export.

    The critical modelling point: every turn re-sends the whole conversation
    so far. A conversation's true cost is not the sum of its message lengths,
    it is the sum over turns of the running prefix. That is quadratic in turn
    count, which is why long threads dominate a bill.

    Counts are estimated from character length unless a .tokens.json sidecar
    is present, in which case measured counts are used instead.
    """
    sidecar = load_sidecar(path)
    if sidecar:
        print(f"  using measured counts for {len(sidecar):,} conversations")

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    if isinstance(data, dict):
        data = data.get("conversations") or data.get("data") or [data]

    convos = []
    for conv in data:
        if not isinstance(conv, dict):
            continue

        msgs = (conv.get("chat_messages") or conv.get("messages")
                or conv.get("mapping") or [])
        if isinstance(msgs, dict):
            msgs = list(msgs.values())
        if not msgs:
            continue

        name = conv.get("name") or conv.get("title") or "(untitled)"
        created = parse_ts(conv.get("created_at") or conv.get("create_time"))
        updated = parse_ts(conv.get("updated_at") or conv.get("update_time"))

        measured = (sidecar or {}).get(name) or {}
        turns = []
        exact = 0
        for i, msg in enumerate(msgs):
            if not isinstance(msg, dict):
                continue
            if "message" in msg and isinstance(msg["message"], dict):
                msg = msg["message"]
            sender = (msg.get("sender") or msg.get("role")
                      or (msg.get("author") or {}).get("role") or "")
            text = flatten_content(
                msg.get("text") or msg.get("content") or msg.get("parts"))
            for att in (msg.get("attachments") or []):
                if isinstance(att, dict):
                    text += flatten_content(att.get("extracted_content"))
            hit = measured.get(str(i))
            if hit:
                tok = int(hit["tokens"])
                exact += 1
            else:
                tok = est_tokens(text)
            turns.append((str(sender).lower(), tok))

        if not turns:
            continue

        written_in = sum(t for s, t in turns if s in ("human", "user"))
        written_out = sum(t for s, t in turns if s not in ("human", "user"))

        # Billable context: prefix re-sent on every assistant response.
        prefix = 0
        billable_in = 0
        for sender, tok in turns:
            if sender in ("human", "user"):
                prefix += tok
                billable_in += prefix
            else:
                prefix += tok

        convos.append({
            "measured": exact,
            "name": name,
            "created": created,
            "updated": updated,
            "turns": len(turns),
            "written_in": written_in,
            "written_out": written_out,
            "billable_in": billable_in,
            "total": billable_in + written_out,
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

INK = "#1f1d1a"
ACCENT = "#c96442"
MUTED = "#8a8580"
GRID = "#e4e0d9"


def bar_chart(pairs, title, width=760, row_h=30, fmt=lambda v: f"{v:,.0f}"):
    if not pairs:
        return f"<p class='empty'>No data for {escape(title)}.</p>"
    label_w = 250
    peak = max(v for _, v in pairs) or 1
    height = row_h * len(pairs) + 20
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{escape(title)}" class="chart">']
    for i, (label, value) in enumerate(pairs):
        y = i * row_h + 10
        bar_w = max(1, (value / peak) * (width - label_w - 110))
        short = label if len(label) <= 34 else label[:33] + "\u2026"
        out.append(
            f'<text x="0" y="{y + 14}" class="lbl">{escape(short)}</text>'
            f'<rect x="{label_w}" y="{y + 3}" width="{bar_w:.1f}" height="16" '
            f'rx="3" fill="{ACCENT}" opacity="0.85"/>'
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
           f'aria-label="{escape(title)}" class="chart">']
    for frac in (0, 0.5, 1):
        y = pad_t + plot_h - frac * plot_h
        out.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - 16}" '
                   f'y2="{y:.1f}" stroke="{GRID}"/>'
                   f'<text x="0" y="{y + 4:.1f}" class="val">'
                   f'{peak * frac / 1000:,.0f}k</text>')
    out.append(f'<path d="{area}" fill="{ACCENT}" opacity="0.12"/>')
    out.append(f'<path d="{path}" fill="none" stroke="{ACCENT}" '
               f'stroke-width="2" stroke-linejoin="round"/>')
    stride = max(1, len(pairs) // 8)
    for i in range(0, len(pairs), stride):
        out.append(f'<text x="{pts[i][0]:.1f}" y="{height - 10}" '
                   f'class="val" text-anchor="middle">'
                   f'{escape(str(pairs[i][0])[-5:])}</text>')
    out.append("</svg>")
    return "".join(out)


CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin:0; padding:40px 24px 80px; background:#faf9f7; color:#1f1d1a;
  font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",sans-serif; }
main { max-width: 860px; margin: 0 auto; }
h1 { font-size:28px; letter-spacing:-.02em; margin:0 0 4px; }
h2 { font-size:13px; text-transform:uppercase; letter-spacing:.1em;
  color:#8a8580; margin:44px 0 14px; font-weight:600; }
.sub { color:#8a8580; margin:0 0 32px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px; }
.card { background:#fff; border:1px solid #e4e0d9; border-radius:10px;
  padding:16px; }
.card b { display:block; font-size:24px; letter-spacing:-.02em; }
.card span { font-size:12px; color:#8a8580; }
.chart { width:100%; height:auto; background:#fff; border:1px solid #e4e0d9;
  border-radius:10px; padding:14px; margin-bottom:8px; }
.lbl { font:12px ui-sans-serif,sans-serif; fill:#1f1d1a; }
.val { font:11px ui-monospace,monospace; fill:#8a8580; }
.note { background:#fff; border-left:3px solid #c96442; padding:12px 16px;
  border-radius:0 8px 8px 0; font-size:13.5px; color:#57534e; margin:16px 0; }
.empty { color:#8a8580; font-style:italic; }
table { width:100%; border-collapse:collapse; font-size:13.5px;
  background:#fff; border:1px solid #e4e0d9; border-radius:10px; }
th,td { padding:9px 12px; text-align:left; border-bottom:1px solid #efece6; }
th { font-size:11px; text-transform:uppercase; letter-spacing:.07em;
  color:#8a8580; }
td.n { text-align:right; font-family:ui-monospace,monospace; }
tr:last-child td { border-bottom:none; }
"""


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
        n_meas = sum(1 for c in chat if c.get("measured"))
        if n_meas:
            h.append("<h2>claude.ai conversations &mdash; measured</h2>")
            h.append(
                f"<div class='note'><b>Measured, not guessed.</b> "
                f"{n_meas:,} of {len(chat):,} conversations were counted "
                "exactly via the free <code>count_tokens</code> endpoint; "
                "the rest fall back to character estimation. Counting cost "
                "zero billable tokens.</div>")
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
                 "<span>est. billable tokens</span></div>"
                 f"<div class='card'><b>{overhead / max(total, 1) * 100:.0f}%</b>"
                 "<span>from context re-send</span></div>"
                 f"<div class='card'><b>{sum(c['turns'] for c in chat):,}</b>"
                 "<span>total turns</span></div></div>")

        h.append("<h2>Heaviest conversations</h2>")
        h.append(bar_chart([(c["name"], c["total"]) for c in chat[:15]],
                           "Heaviest conversations"))

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
            h.append("<h2>Estimated spend over time</h2>")
            h.append(line_chart(sorted(by_day.items())[-60:], "Daily estimate"))

        h.append("<h2>Detail</h2><table><tr><th>Conversation</th>"
                 "<th class='n'>Turns</th><th class='n'>Written</th>"
                 "<th class='n'>Billable</th><th class='n'>Overhead</th></tr>")
        for c in chat[:25]:
            written_c = c["written_in"] + c["written_out"]
            mult = c["total"] / max(written_c, 1)
            h.append(f"<tr><td>{escape(c['name'][:60])}</td>"
                     f"<td class='n'>{c['turns']}</td>"
                     f"<td class='n'>{written_c:,}</td>"
                     f"<td class='n'>{c['total']:,}</td>"
                     f"<td class='n'>{mult:.1f}&times;</td></tr>")
        h.append("</table>")

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
