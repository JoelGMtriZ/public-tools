# Bastion — Command Cheatsheet

The scout that maps the castle. Terminal-first, pipe-friendly. Passive by
default; active only behind an explicit `--scope`.

---

## Mental model (30 seconds)

- **Input**: one or many seeds — domain / URL / IP / CIDR / list file / stdin.
- **Two switches**:
  - *passive → active* (`--active`): do we send packets at the target?
  - *black → grey* (`--cookie/--bearer/--auth`): do we hold target creds?
- **Output**: ranked **leads** (impact × exploitability) grouped into **avenues
  of approach**. Terminal by default; `--ndjson` to pipe; `--html` to share.
- **Safety**: active mode refuses to run without a `--scope` file that covers
  the target, and every active probe is checked against it per host.

---

## Quickest starts

```bash
bastion example.com                      # black-box passive recon, to terminal
bastion example.com --brief              # same, plus a local-LLM scout's summary
bastion example.com --html report.html   # + a shareable HTML report
```

---

## 1. Inputs — how the engagement starts

```bash
bastion example.com                          # single domain
bastion https://app.example.com/login        # URL (stripped to its host)
bastion 203.0.113.10                          # single IP
bastion 203.0.113.0/24                        # a subnet
bastion a.com b.com c.com 203.0.113.0/24      # several seeds → ONE engagement
bastion -l scope.txt                          # a list file
cat scope.txt | bastion -                     # seeds from stdin
bastion -l - < scope.txt                       # same, explicit
```

List-file format (also used by `--scope`): one entry per line, `#` comments,
comma/space separated allowed.

```
# in-scope
*.example.com
example.com
203.0.113.0/24
```

> Multiple seeds fold into a single engagement graph, so shared infrastructure
> across the scope is correlated instead of split across reports.

---

## 2. Passive vs Active

```bash
# Passive (default): third-party OSINT only, target never sees you
bastion example.com

# Active: put packets on the target — REQUIRES --scope
bastion example.com --active --scope scope.txt

# Active + templated vuln checks (nuclei). Loudest thing Bastion does; opt-in twice.
bastion example.com --active --scope scope.txt --nuclei
#   (--nuclei implies --active)
```

Active collectors: port scan (naabu if present, else async connect scan), raw
TLS version prober, HTTP fingerprint, subfinder, nuclei.

---

## 3. Grey-box — once you have target credentials

Any one of these promotes the run to grey-box and unlocks authenticated
collection (authenticated HTTP + authenticated nuclei templates):

```bash
bastion example.com --active --scope scope.txt --bearer "$TOKEN"
bastion example.com --active --scope scope.txt --cookie "session=abc123; csrf=xyz"
bastion example.com --active --scope scope.txt --auth "user:pass"          # HTTP basic
bastion example.com --active --scope scope.txt --header "X-API-Key: $KEY"  # repeatable
```

> Recon-source API keys (Shodan/Censys/…) are the scout's own kit and are always
> used — they do **not** make a run grey-box. Only *target* creds do.

---

## 4. Internet vs Internal targets

```bash
# Internal / air-gapped: disable every third-party internet source.
# Bastion then talks only to your targets and your DNS resolver.
bastion -l internal.txt --active --scope internal.txt --offline

# Internal is usually active-driven (public sources have no RFC1918 data).
# Point your resolver at internal DNS for name resolution.
```

---

## 5. Local LLM — attack-path synthesis (optional)

```bash
bastion example.com --llm                 # enable synthesis (uses configured endpoint)
bastion example.com --brief               # alias for --llm
bastion example.com --llm --llm-url http://localhost:11434/v1
bastion example.com --llm --llm-model qwen3:8b

# First-time bootstrap: detect Ollama, offer to install it, pull a model.
# Consent-gated at each step; add --yes for automation.
bastion example.com --llm --llm-setup
bastion example.com --llm --llm-setup --llm-tier balanced --yes

# Just set up a model, do nothing else:
bastion --llm-setup --llm-tier small

# List the model tiers and exit:
bastion --llm-tiers
```

**Model tiers** (default = `small` / qwen3:8b):

| tier      | model          | ~size | fits            |
|-----------|----------------|-------|-----------------|
| min       | llama3.1:8b    | 5 GB  | CPU / 8 GB RAM  |
| small ◀   | qwen3:8b       | 5 GB  | 8 GB VRAM       |
| balanced  | gpt-oss:20b    | 13 GB | 16 GB VRAM      |
| moe       | qwen3:30b-a3b  | 18 GB | 24 GB VRAM      |

Env overrides: `BASTION_LLM_URL`, `BASTION_LLM_MODEL`, `BASTION_LLM_KEY`.

> The LLM never produces or gates a finding — it summarises and hypothesises
> chains over leads the deterministic engine already found. If the endpoint is
> down, the run degrades silently to deterministic narratives.

---

## 6. Output formats

```bash
bastion example.com                       # colored terminal (default)
bastion example.com --no-color            # plain terminal (for logs/files)
bastion example.com --top 50              # show 50 leads instead of 25

bastion example.com --ndjson              # one JSON lead per line (quiet; to pipe)
bastion example.com --json                # full JSON to stdout
bastion example.com --json out.json       # full JSON to a file
bastion example.com --html report.html    # shareable HTML report (fort plan)

# combine: terminal + artifacts in one run
bastion example.com --active --scope scope.txt --html report.html --json out.json
```

---

## 7. Piping recipes (NDJSON)

```bash
# High-value leads only
bastion example.com --ndjson | jq 'select(.priority > 8)'

# Just RCE / takeover
bastion example.com --ndjson | jq 'select(.impact=="RCE" or .impact=="Takeover")'

# Confirmed findings (verified by a probe or nuclei)
bastion example.com --active --scope s.txt --nuclei --ndjson \
  | jq 'select(.exploitability=="Confirmed")'

# Pull just the assets to hit, one per line
bastion example.com --ndjson | jq -r '.asset' | sort -u

# Feed targets straight into another tool
bastion example.com --ndjson | jq -r 'select(.zone=="postern") | .asset' | httpx -silent

# Count leads by impact
bastion example.com --ndjson | jq -r '.impact' | sort | uniq -c | sort -rn

# Chain Bastion → its own next run (grey-box promotion after finding a token)
bastion example.com --active --scope s.txt --bearer "$(cat token.txt)" --ndjson
```

---

## 8. Network / firewall (self-describing)

```bash
bastion --egress                 # human-readable outbound allowlist
bastion --egress --json          # machine-readable (for automation/tickets)
```

Prints exactly which endpoints Bastion may contact, grouped by setup vs.
per-run and by which key/feature triggers each. Snapshot lives in `NETWORK.md`.

---

## 9. Misc / housekeeping

```bash
bastion example.com --cache /tmp/engagement.sqlite   # cache/run-history location
bastion example.com -v                                # verbose (INFO)
bastion example.com -vv                               # debug
bastion --help
```

---

## Recon-source API keys (env vars — all optional)

Bastion runs with none of these (crt.sh + DNS always work). Add keys to widen
passive coverage.

```bash
export SHODAN_API_KEY=...
export CENSYS_PAT=...            # or CENSYS_API_ID + CENSYS_API_SECRET
export SECURITYTRAILS_API_KEY=...
export VT_API_KEY=...            # VirusTotal
export URLSCAN_API_KEY=...
export RECORDED_FUTURE_API_KEY=...
```

---

## Full-engagement examples

```bash
# Bug bounty: whole program scope, passive first pass, shareable report
bastion -l program-scope.txt --brief --html recon.html

# Bug bounty: active sweep + vuln checks, machine-readable for triage
bastion -l program-scope.txt --active --scope program-scope.txt --nuclei \
  --json findings.json --html recon.html

# Web-app assessment, grey-box after login, with synthesis
bastion https://app.target.com --active --scope app-scope.txt \
  --cookie "$SESSION" --llm --html app-recon.html

# Internal network pentest, offline, active only
bastion -l internal-ranges.txt --active --scope internal-ranges.txt \
  --offline --html internal-recon.html --json internal.json
```

---

## The two things that keep it legal

1. **No `--scope`, no active probing.** `--active`/`--nuclei` hard-fail without
   a scope file, and a target outside the file is refused.
2. **Per-host enforcement.** Every active probe re-checks its destination
   against the scope before a packet moves — including hosts discovered mid-run.

*For authorised engagements only.*

---

## 10. Scan modes (timing/breadth)

```bash
bastion example.com --active --scope s.txt --mode stealth      # slow, low, jittered
bastion example.com --active --scope s.txt --mode balanced     # default
bastion example.com --active --scope s.txt --mode aggressive   # fast, wide, loud
```

| mode | concurrency | ports | naabu rate | nuclei rate | nmap | jitter |
|------|-------------|-------|-----------|-------------|------|--------|
| stealth | 8 | top-100 | 50 | 20 | -T1 | 250 ms |
| balanced | 64 | top-1000 | 500 | 150 | -T3 | — |
| aggressive | 300 | full | 2000 | 500 | -T4 | — |

## 11. SMB enumeration + share looting (IP / CIDR)

```bash
# Enumerate shares on a subnet and loot readable ones for creds/keys (read-only)
bastion 10.0.0.0/24 --active --scope internal.txt

# With found domain creds, authenticated enumeration
bastion 10.0.0.0/24 --active --scope internal.txt --auth "CORP\\user:Password1"
```

Reports shares, readability, and any credentials/keys found in readable files —
values are **redacted** and never exfiltrated; you get the location to retrieve
them deliberately. Needs `netexec`/`smbclient` on the box.

## 12. LAN device recon (network-native)

```bash
bastion 10.0.0.0/24 --active --scope internal.txt      # includes mDNS + cameras
```

- **mDNS/AirPlay/Bonjour**: AirPlay receivers, Chromecasts, printers, VNC, HomeKit.
- **CCTV/IP cameras**: vendor fingerprint (Hikvision/Dahua/Axis/…) + default-cred flags (no brute-forcing).

## 13. RF / proximity recon (Bluetooth, BLE, AirDrop)

```bash
# Requires a Bluetooth adapter AND explicit physical authorisation.
bastion example.com --rf-authorized
```

Passive presence only — enumerates devices advertising nearby; no pairing,
connecting, or attacking. Gated on `--rf-authorized` (separate from `--scope`)
because it captures bystander devices. Needs `bluetoothctl`/`hcitool`/`bettercap`;
AirDrop additionally needs an AWDL stack (`owl`). Findings land in **The Environs**.

## 14. Setup & interfaces

```bash
bastion --install-tools               # install missing scanners (sudo prompts YOU)
bastion --install-tools --dry-run     # show the exact commands, install nothing
bastion --configure-keys              # interactively set recon-source API keys
bastion --export-keys                 # write keys into subfinder's config format
bastion --web                          # launch the localhost control panel (:8899)
bastion --web --web-port 9000
```

The installer never handles your sudo password — privileged steps run `sudo <cmd>`
and sudo prompts you on its own terminal. The web panel binds to 127.0.0.1 and
embeds a per-session access token in the page.
