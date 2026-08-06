#!/usr/bin/env python3
"""
analysis.py -- the insight layer for the Claude token audit.

The audit (claude_token_audit.py) measures where tokens went. This module turns
those measurements into plain-language findings and recommendations: how many
times each early message was re-paid, where a conversation should have been
split, when the running context crossed an expensive threshold, how much of the
cost was attachments, and which conversations were anomalous spikes.

NON-NEGOTIABLES (see PROJECT.md)
  1. No LLM in the analysis path. Arithmetic and thresholds only.
  3. Never present an estimate as a measurement. Every finding carries the
     provenance (coverage) of the conversation it came from, and attachment
     figures -- which are allocated by character fraction -- are always flagged
     as approximate.

INPUT
  The enriched conversation dicts produced by
  claude_token_audit.analyze_chat_export(). Each must carry a "turns_tok" list
  of (role, tokens, attachment_tokens) tuples. Everything here is a pure
  function of that vector; there is no network and no file I/O except the
  optional standalone CLI at the bottom.

STANDALONE (handy for eyeballing findings without building the HTML)
  python3 analysis.py conversations.json
"""

from statistics import median

# --------------------------------------------------------------------------
# Tunables. These are thresholds, not magic -- they decide when a finding is
# worth surfacing, and are deliberately conservative so the report does not
# nag about trivial savings.
# --------------------------------------------------------------------------

SPLIT_MIN_SAVINGS_PCT = 15.0     # only recommend a split above this % of billable
SPLIT_MIN_SAVINGS_TOK = 20_000   # ...and above this absolute token saving
CONTEXT_KNEE_TOKENS   = 50_000   # "from here on, every exchange re-sends 50k+"
SPIKE_MULT            = 3.0      # conversation total > median * this = a spike
TOP_CONVERSATIONS     = 25       # how many heaviest conversations to analyse


def _is_user(role):
    return role in ("human", "user")


def user_ordinal(turns, turn_index):
    """Translate a raw turn index into 'your Nth message'.

    The split point always lands on a user turn. People count their own
    messages, not the interleaved assistant replies, so 'turn 6' is really
    'your 4th message'. Returns that 1-based ordinal.
    """
    return sum(1 for i in range(turn_index + 1) if _is_user(turns[i][0]))


def ordinal_label(n):
    """1 -> '1st', 2 -> '2nd', 4 -> '4th'."""
    n = int(n)
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def snippet(text, words=10, chars=70):
    """A short, single-line quote so the user can find the message."""
    if not text:
        return ""
    clean = " ".join(str(text).split())
    short = " ".join(clean.split(" ")[:words])
    if len(short) > chars:
        short = short[:chars].rstrip()
    if short != clean:
        short += "…"
    return short


# --------------------------------------------------------------------------
# Core arithmetic. Each function takes the per-turn vector and nothing else.
# --------------------------------------------------------------------------

def billable_in(turns):
    """Sum over user turns of the running prefix -- the re-send cost.

    Identical model to analyze_chat_export: every user turn triggers an API
    call whose input is the whole conversation so far. Kept here so a
    split-simulation can recompute the cost of an arbitrary sub-conversation.
    """
    prefix = 0
    total = 0
    for role, tok, _a in turns:
        prefix += tok
        if _is_user(role):
            total += prefix
    return total


def resend_profile(turns):
    """Per-message decomposition: how many billable calls re-sent each message.

    A message at position i is included in the input of every user turn at
    position >= i. So its tokens are paid `times_paid` times, where times_paid
    is the number of user turns from i onward. Summing tok * times_paid over
    all messages reproduces billable_in exactly -- this is that same number,
    attributed back to the messages responsible for it.
    """
    n = len(turns)
    user_suffix = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        user_suffix[i] = user_suffix[i + 1] + (1 if _is_user(turns[i][0]) else 0)

    profile = []
    for i, (role, tok, attach) in enumerate(turns):
        times = user_suffix[i]
        profile.append({
            "index": i,
            "role": role,
            "tok": tok,
            "attach_tok": attach,
            "times_paid": times,
            "billable": tok * times,
            "attach_billable": attach * times,
        })
    return profile


def best_split(turns):
    """Simulate starting a fresh conversation at each user-turn boundary.

    Splitting at turn t means messages before t stop being re-sent by the turns
    after t. Returns (base_cost, best) where best = {turn, savings} for the
    boundary that saves the most, or None if no boundary helps.
    """
    base = billable_in(turns)
    best = None
    for t in range(1, len(turns)):
        if not _is_user(turns[t][0]):
            continue  # a new conversation must begin with a user message
        split_cost = billable_in(turns[:t]) + billable_in(turns[t:])
        savings = base - split_cost
        if savings > 0 and (best is None or savings > best["savings"]):
            best = {"turn": t, "savings": savings}
    return base, best


def context_knee(turns, ceiling=CONTEXT_KNEE_TOKENS):
    """First user turn whose re-sent context exceeds `ceiling` tokens."""
    prefix = 0
    for i, (role, tok, _a) in enumerate(turns):
        prefix += tok
        if _is_user(role) and prefix >= ceiling:
            return {"turn": i, "context": prefix}
    return None


def attachment_cost(turns):
    """Estimated attachment share of billable input. Always approximate."""
    prof = resend_profile(turns)
    attach_tok = sum(p["attach_tok"] for p in prof)
    if attach_tok <= 0:
        return None
    attach_billable = sum(p["attach_billable"] for p in prof)
    total_billable = sum(p["billable"] for p in prof) or 1
    return {
        "tokens": attach_tok,
        "billable": attach_billable,
        "pct": attach_billable / total_billable * 100,
    }


# --------------------------------------------------------------------------
# Assembly: one findings dict per conversation, then account-level rollups.
# --------------------------------------------------------------------------

def conversation_findings(convo):
    turns = convo.get("turns_tok") or []
    texts = convo.get("turns_text") or []
    prof = resend_profile(turns)
    base, split = best_split(turns)

    worst = max(prof, key=lambda p: p["billable"]) if prof else None
    first_user = next((p for p in prof if _is_user(p["role"])), None)

    recommend_split = None
    if split and base > 0:
        pct = split["savings"] / base * 100
        if split["savings"] >= SPLIT_MIN_SAVINGS_TOK and pct >= SPLIT_MIN_SAVINGS_PCT:
            t = split["turn"]
            quote = snippet(texts[t]) if t < len(texts) else ""
            recommend_split = {"turn": t,
                               "message_no": user_ordinal(turns, t),
                               "quote": quote,
                               "savings": split["savings"], "pct": pct}

    return {
        "key": convo.get("key"),
        "name": convo.get("name", "(untitled)"),
        "coverage": convo.get("coverage", 0.0),
        "turns": convo.get("turns", len(turns)),
        "created": convo.get("created"),
        "billable_in": base,
        "total": convo.get("total", base),
        "written": convo.get("written_in", 0) + convo.get("written_out", 0),
        "worst_message": worst,
        "first_user_message": first_user,
        "split": recommend_split,
        "knee": context_knee(turns),
        "attachment": attachment_cost(turns),
    }


def account_findings(convos, top=TOP_CONVERSATIONS):
    """Whole-export rollup. `convos` is expected sorted by total desc."""
    ranked = [c for c in convos if c.get("turns_tok")]
    per_conversation = [conversation_findings(c) for c in ranked[:top]]

    totals = [c["total"] for c in convos if c.get("total", 0) > 0]
    med = median(totals) if totals else 0.0

    spikes = []
    if med > 0:
        for c in convos:
            if c.get("total", 0) > med * SPIKE_MULT:
                spikes.append({
                    "key": c.get("key"),
                    "name": c.get("name", "(untitled)"),
                    "total": c["total"],
                    "mult": c["total"] / med,
                    "coverage": c.get("coverage", 0.0),
                    "created": c.get("created"),
                })
        spikes.sort(key=lambda s: -s["mult"])

    total_split_savings = sum(f["split"]["savings"]
                              for f in per_conversation if f["split"])

    return {
        "per_conversation": per_conversation,
        "median_total": med,
        "spikes": spikes[:10],
        "spike_mult": SPIKE_MULT,
        "total_split_savings": total_split_savings,
        "split_count": sum(1 for f in per_conversation if f["split"]),
    }


# --------------------------------------------------------------------------
# Standalone CLI -- text output, no HTML. Reuses analyze_chat_export so the
# token-derivation logic lives in exactly one place.
# --------------------------------------------------------------------------

def _fmt(n):
    return f"{n:,.0f}"


def main():
    import sys
    if len(sys.argv) < 2:
        sys.exit("usage: python3 analysis.py conversations.json")

    import claude_token_audit as cta  # local import avoids an import cycle
    convos = cta.analyze_chat_export(sys.argv[1])
    af = account_findings(convos)

    print(f"\n  analysed {len(af['per_conversation'])} heaviest of "
          f"{len(convos):,} conversations")
    print(f"  median conversation: {_fmt(af['median_total'])} tokens")
    if af["total_split_savings"] > 0:
        print(f"  potential savings from {af['split_count']} recommended "
              f"split(s): ~{_fmt(af['total_split_savings'])} tokens\n")

    for f in af["per_conversation"]:
        if not (f["split"] or f["knee"] or f["attachment"]):
            continue
        print(f"  - {f['name'][:60]}")
        print(f"      billable {_fmt(f['billable_in'])} tok over {f['turns']} turns"
              f"  ({'measured' if f['coverage'] >= 0.99 else 'estimated'})")
        fu = f["first_user_message"]
        if fu and fu["times_paid"] > 1:
            print(f"      first message re-sent {fu['times_paid']} times "
                  f"(~{_fmt(fu['billable'])} tok)")
        if f["split"]:
            sp = f["split"]
            where = (f"after your {ordinal_label(sp['message_no'])} message"
                     if sp.get("message_no") else f"at turn {sp['turn']}")
            print(f"      start a fresh chat {where} -> save "
                  f"~{_fmt(sp['savings'])} tok ({sp['pct']:.0f}%)")
            if sp.get("quote"):
                print(f"        (that message begins: \"{sp['quote']}\")")
        if f["knee"]:
            print(f"      context crossed {_fmt(CONTEXT_KNEE_TOKENS)} at turn "
                  f"{f['knee']['turn']} (was {_fmt(f['knee']['context'])})")
        if f["attachment"]:
            print(f"      attachments ~{f['attachment']['pct']:.0f}% of billable "
                  f"(~{_fmt(f['attachment']['billable'])} tok, approx.)")

    if af["spikes"]:
        print(f"\n  spikes (> {af['spike_mult']:g}x median):")
        for s in af["spikes"]:
            print(f"    {s['mult']:.1f}x  {s['name'][:60]}  "
                  f"({_fmt(s['total'])} tok)")
    print()


if __name__ == "__main__":
    main()
