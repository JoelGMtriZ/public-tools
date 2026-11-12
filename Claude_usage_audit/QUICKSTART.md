# Quickstart — personal Pro/Max account

Runbook for your first audit. Roughly 20 minutes of work, most of it waiting
for an email.

---

## Before you start

Four files, all in one folder. They import each other, so don't split them up.

```
~/token-audit/
  analysis.py
  chatexport.py
  claude_token_audit.py
  exact_count.py
```

If you cloned the repo instead, keep your export and reports **outside** the
repo folder so they can't be committed by accident.

Python 3.9 or newer. Nothing to install — standard library only.

```bash
python3 --version
```

---

## Stage 1 — Get the export

1. Open **claude.ai in a browser** on your personal account.
   Not the phone app; export isn't available there.
2. Click your initials, bottom left → **Settings** → **Privacy**
3. Click **Export data**
4. Wait for the email. Minutes if you're light, longer if you have years of history.
5. Download the ZIP. **The link dies after 24 hours.**
6. Unzip it. You want `conversations.json`.

```bash
mkdir -p ~/token-audit && cd ~/token-audit
cp ~/Downloads/data-*/conversations.json .
```

**Sanity check before going further:**

```bash
python3 -c "
import json
d = json.load(open('conversations.json'))
print(f'{len(d)} conversations')
print('has uuid:', 'uuid' in d[0])
print('sample:', d[0].get('name') or '(untitled)')
"
```

If `has uuid` prints `False`, the export format has changed. The report will
still run, but exact counts won't carry over between exports. Please open an
issue with the top-level key names (not the contents).

---

## Stage 2 — First report, no API key needed

```bash
python3 claude_token_audit.py conversations.json
open claude_token_audit.html          # macOS
# xdg-open claude_token_audit.html    # Linux
# start claude_token_audit.html       # Windows
```

Nothing leaves your machine. No account, no key, no network.

The report includes your conversation titles and short message snippets, so
look it over before sharing it with anyone.

### Reading it

The header will say **estimated** — correct, and don't over-trust the absolute
numbers yet. What *is* trustworthy right now:

| What to look at | What it tells you |
|---|---|
| **Heaviest conversations** | Where your tokens actually went |
| **Overhead multiplier** | How many times you paid for the same text |
| **Context overhead split** | Total waste from long threads |
| **Daily chart** | Which days spiked, and what you were doing |

Start with the multiplier column in the detail table.

- **under 4×** — healthy, short focused chats
- **4–8×** — normal for real work
- **8–15×** — you should have started a new chat partway through
- **over 15×** — one thread is quietly dominating your usage

---

## Stage 3 — Exact counts (optional)

Only worth doing if the estimates look off, or you want numbers you'd put in
front of your team. Especially relevant for script-heavy chats: code tokenizes
very differently from prose, so character estimation drifts most exactly where
your usage is heaviest.

> **Privacy:** this stage sends the text of each message to Anthropic's
> `count_tokens` API to be counted. Only the token counts are stored locally;
> no message text is cached. Skip this stage if you'd rather nothing leave
> your machine.

### Get a key

The Console is a **separate account** from your claude.ai login. Pro and Max
plans include no API access.

1. Sign up at **console.anthropic.com**
2. Verify by SMS. No card needed. VoIP and Google Voice numbers are rejected.
3. **API Keys** → create one → copy it immediately, it's shown once

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Counting is billed at zero, so this won't spend credits. If you have the $5
trial credit sitting there, don't claim it yet — it expires 14 days after you
activate it and you don't need it for this.

### Test small first

```bash
python3 exact_count.py conversations.json --limit 50
```

Expect: a count of messages found, then progress. If it stops with
"API key rejected", the key is wrong. If it crawls, that's rate limiting on an unfunded account, not a
bug — the script backs off and retries on its own.

### Validate the math

```bash
python3 exact_count.py conversations.json --calibrate 10
```

This checks an assumption the tool makes: it counts each message once and adds
them up, rather than re-counting the whole thread at every turn (which would be
hundreds of times more API calls). Tokenization isn't perfectly additive, so
this measures the error on *your* data instead of asking you to trust a fixed
constant.

- **drift under 2%** — good, carry on
- **2–5%** — usable, treat totals as approximate
- **over 5%** — the shortcut doesn't fit your data well; please open an issue
  with the drift figures (no conversation content needed)

### Full run

```bash
python3 exact_count.py conversations.json
python3 claude_token_audit.py conversations.json
```

First command may take a while on a large history. It only happens once —
results are cached in `~/.cache/claude-token-audit/counts.db`, and every later
run is instant and offline.

The report header should now read **measured**.

---

## Stage 4 — Re-running later

Export again in a month and just repeat Stage 3. Chats you already counted are
matched by `uuid` and cost nothing; only new messages hit the network. Coverage
percentages in the report show you exactly what was reused.

---

## Troubleshooting

**`ModuleNotFoundError: chatexport`** (or `analysis`)
All four files must be in the same folder, and you must run from that folder.

**Report says "estimated" after running exact_count**
The `.tokens.json` sidecar has to sit beside the export with a matching name.
`conversations.json` pairs with `conversations.tokens.json`.

**"written by an older schema"**
Expected after an upgrade. Re-run `exact_count.py`; the cache still applies, so
it's fast.

**Coverage stuck below 100%**
Some messages errored during counting. Re-run — cached messages are skipped and
only the failures retry.

**Report is empty**
The export layout may differ from what the reader expects. Check the sanity
snippet in Stage 1 and open an issue with the top-level key names.

---

## What to do with the results

The point isn't the totals, it's the habit change:

1. **Split long threads.** The single biggest lever. When you change topic,
   start a new chat — you're re-paying for everything above.
2. **Watch attachments.** A pasted script is re-sent on every subsequent turn,
   not just the one you pasted it in.
3. **Front-load constraints.** Saying "stdlib only, sandboxed, no stdin" up
   front is cheaper than two rejected drafts.
