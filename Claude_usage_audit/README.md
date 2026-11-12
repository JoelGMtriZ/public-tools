# Claude token audit

**Where do your claude.ai chat tokens actually go?** A local, zero-dependency
tool that turns your claude.ai data export into a per-conversation token
report, and shows you which threads to split and where.

- **Local only.** The report is built on your machine. Nothing is uploaded.
- **Zero dependencies.** Python 3.9+, standard library only.
- **Exact counts, optionally.** Estimates by default; exact counts via
  Anthropic's free `count_tokens` endpoint if you want them.

> **Two things to know up front**
> 1. Exact counting needs an Anthropic **API key** (from
>    [console.anthropic.com](https://console.anthropic.com)), even though
>    `count_tokens` is billed at zero. A Pro/Max/Team plan does not include one.
> 2. Exact counting **sends the text of each message to Anthropic's API** to be
>    counted. That's the only step that touches the network, and it's optional.
>    Skip it and everything stays on your machine.

## Why

Every message you send re-sends the whole conversation so far, so a long
thread's cost grows roughly with the square of its length. A 40-turn chat pays
for its first message about 20 times. This tool breaks that down per
conversation. An illustrative finding:

> This conversation cost 412k tokens. 82% of that was re-sent context.
> Your opening message was paid for 41 times.
> Starting a new chat after your 12th message would have saved ~180k.

## Quick start

```bash
git clone https://github.com/JoelGMtriZ/public-tools.git
cd public-tools/Claude_usage_audit

# 1. Export your data: claude.ai (web) -> Settings -> Privacy -> Export data.
#    Unzip the emailed archive and take conversations.json.
#    Keep it OUTSIDE this repo so it can never be committed by accident.

# 2. Estimated report, fully offline
python3 claude_token_audit.py ~/token-audit/conversations.json -o ~/token-audit/report.html

# 3. Optional: exact counts (sends message text to Anthropic's count_tokens API)
export ANTHROPIC_API_KEY=sk-ant-...
python3 exact_count.py ~/token-audit/conversations.json
python3 claude_token_audit.py ~/token-audit/conversations.json -o ~/token-audit/report.html
```

Open the HTML file in any browser. For a step-by-step walkthrough, see
[QUICKSTART.md](QUICKSTART.md).

## What's in the report

- **Optimization findings**: the heaviest conversation in plain language, how
  many times your opening message was re-paid, and a recommended "start a new
  chat here" point with the tokens it would have saved.
- **Spikes**: conversations that ran far above your median.
- **Overhead split**: text actually written vs. context re-sent.
- **Attachment share**: how much of a thread's cost came from attached files
  (always approximate).
- **Provenance on every figure.** Each number is tagged *measured* or
  *estimated*. Charts hatch estimated bars so you can tell which to trust.

## Scripts

All four files must stay in the same folder; they import each other.

| File | What it does |
|---|---|
| `claude_token_audit.py` | Builds the HTML report. Reads `conversations.json` and/or Claude Code logs. |
| `exact_count.py` | Optional. Replaces estimates with exact counts via `count_tokens`. |
| `analysis.py` | The findings engine (arithmetic only). Also runs standalone for a text summary. |
| `chatexport.py` | Shared export reader, so all scripts agree on which message is which. |

### `claude_token_audit.py`

```
python3 claude_token_audit.py PATH [PATH ...] [-o OUT.html]
```

`PATH` can be a `conversations.json` export, a Claude Code projects folder
(`~/.claude/projects`), a single `.jsonl` session log, or several of these.
Default output is `claude_token_audit.html` in the current folder.

### `exact_count.py`

```
python3 exact_count.py conversations.json [--limit N] [--calibrate N]
                                          [--model ID] [--cache PATH]
```

| Flag | Meaning |
|---|---|
| `--limit N` | Only count the first N messages (good for a test run). |
| `--calibrate N` | Compare sum-of-messages vs. whole-conversation counts on your N longest chats, to measure how accurate the per-message shortcut is on your data. |
| `--model ID` | Model whose tokenizer to use (default `claude-sonnet-4-5`). |
| `--cache PATH` | Cache location (default `~/.cache/claude-token-audit/counts.db`). |

Each unique message is counted once and cached by content hash, so re-runs
only count new messages and are otherwise offline. Results go into a
`conversations.tokens.json` sidecar next to the export, which the report picks
up automatically. A rejected API key stops the run immediately; anything
already counted is kept.

### `analysis.py`

```
python3 analysis.py conversations.json
```

Prints the findings as text without building the HTML.

## Claude Code logs (bonus)

Pointing the report at `~/.claude/projects` adds a Claude Code section with
real token counts from the session logs: totals, cache hit rate, per-project
and per-session usage, daily volume, model mix and tool-call frequency.
Repeated log lines for the same API response are counted once. Dollar figures
are **API list-price equivalents** from the table at the top of
`claude_token_audit.py`. They're not what a subscription bills, so check the
table against [current pricing](https://platform.claude.com/docs/en/about-claude/pricing).

For deeper Claude Code analytics, dedicated tools like `ccusage` go further.
This tool's focus is chat.

## How the numbers are computed

- **Billable input** for a conversation = the sum, over each of your
  messages, of everything in the thread up to and including it. Output tokens
  are counted once.
- **Estimates** use ~3.8 characters per token (`CHARS_PER_TOKEN`).
  `exact_count.py` prints your measured ratio so you can tune it.
- **Exact counts** call `count_tokens` once per message and subtract the fixed
  per-request framing (measured once per model), then sum. Tokenization isn't
  perfectly additive across messages; `--calibrate` measures the drift.
- **Not modeled:** system prompts, project knowledge, tool and search results,
  and prompt caching on claude.ai. Real usage is higher than this report
  shows. Treat it as a lower bound and use it to rank conversations.

## Privacy

- The report contains your conversation **titles** and short **snippets** of
  messages (to show where to split). Review it before sharing.
- `conversations.json`, the `.tokens.json` sidecar and generated reports are
  gitignored in this repo, but the safest habit is to keep them outside it.
- The cache stores message hashes and token counts, never message text.

## Limitations

- On Team and Enterprise plans, only the workspace's Primary Owner can export
  data, and that export covers every member.
- Export download links expire after 24 hours.
- The export format is undocumented and may change. If the report comes out
  empty, please open an issue with the top-level key names of your
  `conversations.json` (not its contents).

## License

[MIT](LICENSE)
