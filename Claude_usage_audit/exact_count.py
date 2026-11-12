#!/usr/bin/env python3
"""
exact_count.py -- turn estimated token counts into measured ones.

Anthropic's /v1/messages/count_tokens endpoint is free and rate-limited
separately from generation. That means a chat-export analyzer can report
EXACT input token counts while consuming zero billable tokens.

This module counts each message in a claude.ai export exactly once, caches
the result by content hash, and writes a sidecar file the main analyzer
reads. Re-runs cost nothing: only new messages hit the network.

WHY PER-MESSAGE AND NOT PER-PREFIX
  A conversation's billable cost is the sum over turns of the running
  prefix. Counting every prefix would be O(n^2) API calls. Counting each
  message once is O(n), and prefix sums are then arithmetic. Tokenization
  is not perfectly additive across message boundaries, but the drift is
  small and bounded -- see --calibrate, which measures it on your own data
  instead of asking you to trust a constant.

USAGE
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 exact_count.py conversations.json
  python3 exact_count.py conversations.json --calibrate 20
  python3 claude_token_audit.py conversations.json   # picks up the cache

Only stdlib. No SDK required.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import chatexport

API_URL = "https://api.anthropic.com/v1/messages/count_tokens"
API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-5"
CACHE_PATH = Path.home() / ".cache" / "claude-token-audit" / "counts.db"

# count_tokens rejects empty content, so anything shorter is scored locally.
MIN_COUNTABLE = 1


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def open_cache(path=CACHE_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE IF NOT EXISTS counts (
                    hash TEXT PRIMARY KEY,
                    model TEXT NOT NULL,
                    tokens INTEGER NOT NULL,
                    chars INTEGER NOT NULL,
                    created REAL NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS overhead (
                    model TEXT PRIMARY KEY,
                    tokens INTEGER NOT NULL)""")
    db.commit()
    return db


def request_overhead(db, model, api_key):
    """Fixed tokens count_tokens adds to every request (role/turn framing).

    Each message is counted as its own one-message request, so every raw
    count includes this framing once. Without subtracting it, short messages
    are inflated and totals drift upward with message count. Measured once
    per model by counting a one-character message, then cached.
    """
    row = db.execute("SELECT tokens FROM overhead WHERE model = ?",
                     (model,)).fetchone()
    if row:
        return row[0]
    if not api_key:
        return None
    raw = count_with_retry("a", model, api_key)
    overhead = max(raw - 1, 0)  # "a" itself is one token
    db.execute("INSERT OR REPLACE INTO overhead VALUES (?, ?)", (model, overhead))
    db.commit()
    return overhead


def content_hash(text, model):
    return hashlib.sha256(f"{model}\x00{text}".encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

class RateLimited(Exception):
    pass


class AuthError(Exception):
    """401/403: the key is wrong or lacks access. Retrying cannot help."""


def count_remote(text, model, api_key, timeout=30):
    """One count_tokens call. Returns int. Raises RateLimited on 429."""
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": text}],
    }).encode("utf-8")

    req = urllib.request.Request(
        API_URL, data=payload, method="POST",
        headers={"content-type": "application/json",
                 "anthropic-version": API_VERSION,
                 "x-api-key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(json.loads(resp.read())["input_tokens"])
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RateLimited(exc.headers.get("retry-after", "5"))
        body = exc.read().decode("utf-8", "replace")[:200]
        if exc.code in (401, 403):
            raise AuthError(f"HTTP {exc.code}: {body}") from exc
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc


def count_with_retry(text, model, api_key, max_attempts=6):
    delay = 1.0
    for attempt in range(max_attempts):
        try:
            return count_remote(text, model, api_key)
        except RateLimited as exc:
            try:
                wait = float(str(exc))
            except ValueError:
                wait = delay
            time.sleep(min(wait, 60))
            delay = min(delay * 2, 60)
        except urllib.error.URLError:
            if attempt == max_attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 60)
    raise RuntimeError("exhausted retries")


# --------------------------------------------------------------------------
# Extraction (mirrors claude_token_audit.py)
# --------------------------------------------------------------------------

def iter_messages(export_path):
    """Yield (conv_key, conv_name, index, role, text) for every message."""
    for key, name, _conv, turns in chatexport.load(export_path):
        for index, role, text, _attach_chars in turns:
            yield key, name, index, role, text


# --------------------------------------------------------------------------
# Main counting pass
# --------------------------------------------------------------------------

def run(export_path, model, api_key, cache_path=CACHE_PATH, limit=None):
    db = open_cache(cache_path)
    messages = list(iter_messages(export_path))
    if limit:
        messages = messages[:limit]

    unique = {}
    for _, _, _, _, text in messages:
        if len(text) >= MIN_COUNTABLE:
            unique[content_hash(text, model)] = text

    cached = {row[0] for row in db.execute("SELECT hash FROM counts")}
    todo = [(h, t) for h, t in unique.items() if h not in cached]

    print(f"  {len(messages):,} messages  "
          f"{len(unique):,} unique  "
          f"{len(cached & set(unique)):,} already cached  "
          f"{len(todo):,} to count")

    if todo and not api_key:
        print("\n  ANTHROPIC_API_KEY not set. Counting is free, but the "
              "endpoint still needs a key.\n  Create one at "
              "console.anthropic.com -- count_tokens is billed at zero.",
              file=sys.stderr)
        return None

    overhead = request_overhead(db, model, api_key)
    if overhead is None:
        overhead = 0
        print("  ! request overhead not measured yet (needs ANTHROPIC_API_KEY "
              "once); counts include a few framing tokens per message",
              file=sys.stderr)

    start = time.time()
    try:
        for n, (h, text) in enumerate(todo, 1):
            try:
                tokens = count_with_retry(text, model, api_key)
            except AuthError:
                raise
            except Exception as exc:  # noqa: BLE001 - keep going, log the miss
                print(f"\n  ! {h[:8]}: {exc}", file=sys.stderr)
                continue
            db.execute("INSERT OR REPLACE INTO counts VALUES (?,?,?,?,?)",
                       (h, model, tokens, len(text), time.time()))
            if n % 25 == 0:
                db.commit()
                rate = n / max(time.time() - start, 0.001)
                eta = (len(todo) - n) / max(rate, 0.001)
                print(f"\r  counted {n:,}/{len(todo):,}  "
                      f"{rate:.1f}/s  eta {eta / 60:.1f}m", end="", flush=True)
    finally:
        db.commit()  # keep whatever was counted, even if we stop early
    print()

    # Emit the sidecar the analyzer reads. The cache stores raw counts; the
    # per-request framing is subtracted here so it can be re-measured later.
    lookup = {row[0]: row[1] for row in db.execute("SELECT hash, tokens FROM counts")}
    out = {}
    hits = 0
    for key, _name, idx, _role, text in messages:
        bucket = out.setdefault(key, {})
        if len(text) < MIN_COUNTABLE:
            bucket[str(idx)] = 0  # empty message: exactly zero, no call needed
            hits += 1
            continue
        h = content_hash(text, model)
        if h in lookup:
            bucket[str(idx)] = max(lookup[h] - overhead, 1)
            hits += 1

    sidecar = chatexport.write_sidecar(export_path, model, out)
    print(f"  wrote {sidecar}")
    print(f"  coverage: {hits:,}/{len(messages):,} messages "
          f"({hits / max(len(messages), 1) * 100:.1f}%)")

    rows = list(db.execute("SELECT tokens, chars FROM counts "
                           "WHERE chars > 0 AND model = ?", (model,)))
    if rows:
        ratio = (sum(c for _, c in rows)
                 / sum(max(t - overhead, 1) for t, _ in rows))
        print(f"  measured ratio: {ratio:.2f} chars/token "
              f"across {len(rows):,} messages")
        print("  (update CHARS_PER_TOKEN in claude_token_audit.py to match "
              "your own writing)")
    return sidecar


def calibrate(export_path, model, api_key, sample=20, cache_path=CACHE_PATH):
    """Measure additivity drift: sum-of-parts vs. count-of-whole.

    This is the honesty check. If summing per-message counts diverges badly
    from counting a full conversation, the O(n) shortcut is not safe and the
    report should say so.
    """
    by_conv = {}
    for key, name, _idx, role, text in iter_messages(export_path):
        by_conv.setdefault((key, name), []).append((role, text))

    picks = sorted(by_conv.items(), key=lambda kv: -len(kv[1]))[:sample]
    overhead = request_overhead(open_cache(cache_path), model, api_key) or 0
    print(f"  calibrating on {len(picks)} conversations "
          f"(request overhead: {overhead} tokens)\n")
    drifts = []

    for (_key, name), turns in picks:
        parts = 0
        for _, text in turns:
            if len(text) >= MIN_COUNTABLE:
                parts += max(count_with_retry(text, model, api_key) - overhead, 1)

        merged = []
        for role, text in turns:
            r = "user" if role in ("human", "user") else "assistant"
            if merged and merged[-1]["role"] == r:
                merged[-1]["content"] += "\n" + text
            else:
                merged.append({"role": r, "content": text or " "})
        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": " "})

        payload = json.dumps({"model": model, "messages": merged}).encode()
        req = urllib.request.Request(
            API_URL, data=payload, method="POST",
            headers={"content-type": "application/json",
                     "anthropic-version": API_VERSION, "x-api-key": api_key})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                # The whole conversation is one request: framing paid once.
                whole = int(json.loads(resp.read())["input_tokens"]) - overhead
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthError(f"HTTP {exc.code}") from exc
            print(f"  ! {name[:40]}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {name[:40]}: {exc}")
            continue

        drift = (parts - whole) / max(whole, 1) * 100
        drifts.append(drift)
        print(f"  {name[:44]:<44} parts {parts:>8,}  "
              f"whole {whole:>8,}  {drift:+.2f}%")

    if drifts:
        avg = sum(drifts) / len(drifts)
        worst = max(drifts, key=abs)
        print(f"\n  mean drift {avg:+.2f}%   worst {worst:+.2f}%")
        print("  under ~2% the per-message shortcut is sound; above that, "
              "report a range rather than a point estimate.")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export", help="conversations.json from claude.ai")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--limit", type=int, help="only process first N messages")
    ap.add_argument("--calibrate", type=int, metavar="N",
                    help="measure additivity drift on N conversations")
    ap.add_argument("--cache", default=str(CACHE_PATH))
    args = ap.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    try:
        if args.calibrate:
            if not api_key:
                sys.exit("ANTHROPIC_API_KEY required for calibration")
            calibrate(args.export, args.model, api_key, args.calibrate,
                      args.cache)
        else:
            run(args.export, args.model, api_key, args.cache, args.limit)
    except AuthError as exc:
        sys.exit(f"\n  ! API key rejected ({exc}). Check ANTHROPIC_API_KEY; "
                 "anything counted before this was saved to the cache.")


if __name__ == "__main__":
    main()
