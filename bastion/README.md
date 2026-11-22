# Bastion

> **⚠️ Authorized use only.** Bastion is for security testing you are
> explicitly permitted to perform — your own assets, a signed engagement, or a
> bug-bounty program whose published scope covers the target. Active probing is
> gated behind a scope file for this reason. Using it against systems you do not
> own or have written authorization to test may be illegal. You are solely
> responsible for how you use it. The authors accept no liability (see LICENSE).

An offensive reconnaissance mapper for web-app assessments, network pentests,
and bug-bounty hunting. Bastion plays the part of the scout who rides ahead,
maps the enemy castle — its works, its weak points, and the way in — and hands
the general a marked map, not a grade.

The output is not a defensive posture score. It is a set of **leads**
(attackable observations, each rated by what it yields and how confirmed it is)
organised into ranked **avenues of approach**.

## The model

Everything a collector learns becomes an `Observation`. Observations fold into
deduplicated `Asset`s (hosts, IPs, services, endpoints, certs). Assets are read
for `Lead`s, and leads are grouped into `Avenue`s.

Each lead carries:

- **Impact** — what you gain: Recon < Data < Foothold < Creds < Takeover < RCE
- **Exploitability** — how real it is: Theoretical < Possible < Likely < Confirmed
- **priority** = impact × exploitability — the sort key on the general's map
- a **move** — the scout's recommended next action

Zones are read from the attacker's side of the wall:

| Zone | What you do here |
|------|------------------|
| Curtain Wall | Get behind the edge — find origin the CDN/WAF hides |
| Gatehouse | Attack the locks — auth surfaces to spray or bypass |
| Armory | Break the crypto — downgrade, decrypt, impersonate |
| Banners | Read the colours — versions that tell you what to throw |
| Garrison | Storm a service — exposed daemons with known holes |
| Postern | Slip the side door — forgotten or mis-scoped hosts |
| Sally Port | Turn their own gates — SSRF, callbacks, redirects |
| The Keep | The objective — origin and core assets |
| Scout's Report | Ground intel — leaks, exposure, prior compromise |

## Black-box and grey-box

- **Black-box** (default): no target credentials. Passive OSINT plus, with
  `--active`, unauthenticated probing.
- **Grey-box**: supply target credentials you have obtained
  (`--cookie` / `--bearer` / `--auth` / `--header`) and Bastion promotes the run
  — authenticated HTTP fingerprinting and authenticated nuclei templates fire.

Recon-source API keys (Shodan, Censys, ...) are the scout's own kit and are
always used in either box; they are *not* what makes a run grey-box.

## Passive vs active

Passive collectors never touch the target: crt.sh, DNS, Shodan, Censys,
SecurityTrails, VirusTotal, urlscan, Recorded Future.

Active collectors (`--active`, and only with a `--scope` file that covers the
target) put packets on the target:

- **portscan** — asyncio connect scan, or `naabu` when present
- **tlsprobe** — a raw-ClientHello prober (see below)
- **httpfinger** — HTTP status/title/tech, auth-aware in grey-box
- **subfinder** — extra subdomain sources (needs the binary)
- **nuclei** — templated vuln/misconfig checks, behind `--nuclei` (needs the binary)

On Kali/Parrot the full toolchain is present, so Bastion orchestrates the
battle-tested binaries where they win (naabu, nuclei, subfinder) and parses
their JSON, using pure Python only where it is competitive and needs the
response objects itself.

### The raw TLS prober

`tlsprobe` writes ClientHello bytes over a plain socket and reads the
ServerHello directly, rather than using stdlib `ssl`. This is deliberate:
system OpenSSL 3.x refuses to negotiate SSLv3/TLS 1.0/1.1, so a stdlib scan
returns false negatives on exactly the obsolete-protocol findings you want.
The raw prober bypasses OpenSSL policy and correctly flags legacy listeners.

## Scope

Active probing requires a bug-bounty-style scope file (`--scope scope.txt`):

```
*.example.com
example.com
203.0.113.0/24
!admin.example.com      # explicitly out of scope
!203.0.113.5
```

Every active collector validates each destination against this file before a
packet moves. No scope, no active probing — enforced at selection and per host.

## Attack-path synthesis (optional, local LLM)

With `--llm`, Bastion sends the *already-structured* leads to any
OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM — a local ~30–40B MoE is
ample) and asks for a short brief plus hypothesised chains. It never produces or
gates a finding; chains are validated by lead id, so the model cannot introduce
assets that were not found. On any failure it degrades silently to the
deterministic narratives. Off by default.

```
export BASTION_LLM_URL=http://localhost:11434/v1
export BASTION_LLM_MODEL=qwen2.5:32b
bastion example.com --active --scope scope.txt --llm --brief
```

## Inputs

An engagement starts from one or many seeds. Bastion takes a single target or a
whole scope, and mixes types freely:

```
bastion example.com                         # one domain
bastion https://app.example.com/login       # a URL (stripped to its host)
bastion 203.0.113.0/24                       # a subnet
bastion a.com b.com 203.0.113.0/24           # several seeds at once
bastion -l scope.txt                         # a list file (one per line)
cat scope.txt | bastion -                    # seeds from stdin
```

Multiple seeds fold into **one engagement graph**, so shared infrastructure
across a scope — an IP backing three in-scope brands, a cert tying two together
— is correlated rather than split across separate reports. List files accept
`#` comments and comma- or whitespace-separated entries.

## Internet and internal targets

Bastion recons both. Public sources (crt.sh, Shodan, ...) hold no data on
RFC1918 space, so internal engagements lean on active mode. For a fully
air-gapped or sensitive internal run, add `--offline`: every third-party recon
source is disabled and Bastion talks only to your targets and your DNS resolver
— nothing leaves the network. Point DNS at your internal resolvers.

## Network / firewall

Bastion is self-describing about its egress. To learn exactly what to open on
an internal firewall:

```
bastion --egress            # grouped, human-readable
bastion --egress --json     # machine-readable
```

This is generated from the tool's own source list, so it never drifts from what
the code actually contacts. See `NETWORK.md` for a snapshot. Target traffic is
separate and bounded by `--scope`.

## Bundling a local model

`--llm` uses whatever OpenAI-compatible endpoint is configured. If you want
synthesis but have nothing set up, `--llm-setup` bootstraps a local one — it
detects Ollama, offers to install it (showing the official command first),
starts the service, and pulls a right-sized model. Every step is consent-gated;
`--yes` skips the prompts for automation.

Weights are **not** bundled in the package (that would be gigabytes); they are
pulled on demand and cached by Ollama. The tool itself stays light — the base
install is two pure-Python dependencies (~6 MB); the ML analysis extra
(numpy/scikit-learn, ~195 MB) is optional (`pip install bastion[ml]`) and Bastion
degrades gracefully without it.

Pick a model tier by hardware (`--llm-tiers` to list):

| Tier | Model | Footprint | Fits |
|------|-------|-----------|------|
| min | llama3.1:8b | ~5 GB | CPU / 8 GB RAM |
| small *(default)* | qwen3:8b | ~5 GB | 8 GB VRAM |
| balanced | gpt-oss:20b | ~13 GB | 16 GB VRAM |
| moe | qwen3:30b-a3b | ~18 GB | 24 GB VRAM |

The synthesis task is reasoning over already-structured leads — it does not need
the model to *know* CVEs (nuclei does that), so a small instruct model is
enough. The `moe` tier is a 30B-total / ~3B-active mixture-of-experts: near-30B
reasoning at roughly 7B speed, if you have the VRAM to hold it.

## Scan modes

`--mode stealth|balanced|aggressive` (default balanced) sets timing and breadth
for active work — concurrency, port range, connect/nuclei rates, per-probe
jitter, and the `-T` flag handed to nmap. Stealth trades completeness for a low,
jittered footprint; aggressive does the opposite.

## SMB, LAN devices, and RF recon

Active mode against IPs/CIDRs adds several collectors beyond port/TLS/HTTP:

- **SMB** — enumerates shares (netexec/smbclient), flags readable ones, and loots
  readable shares for credentials and keys with a read-only pattern+entropy
  scanner. Found secrets are reported **redacted, with their location** — never
  exfiltrated.
- **mDNS/Bonjour** — discovers AirPlay receivers, Chromecasts, printers, VNC,
  HomeKit and other advertised services on the local segment (a real multicast
  query, no dependency).
- **CCTV / IP cameras** — fingerprints cameras and NVRs by port and banner
  (Hikvision, Dahua, Axis, Reolink, …) and flags known default credentials for
  the vendor. It does not attempt logins.
- **Bluetooth / BLE / AirDrop** — proximity recon, **off unless you pass
  `--rf-authorized`**. This is gated separately from `--scope` because it
  captures devices belonging to bystanders, needs a Bluetooth adapter, and is
  strictly passive presence detection (no pairing, connecting, or attacking).
  AirDrop needs an AWDL stack (`owl`) for full coverage. These findings land in a
  dedicated zone, *The Environs*.

## API keys, one file

`bastion --configure-keys` walks you through the optional recon-source keys and
stores them at `~/.config/bastion/keys.env` (mode 0600). `bastion --export-keys`
writes them into the formats other tools expect (e.g. subfinder's
`provider-config.yaml`). Real environment variables always override the file.

## Installing the scanners

`bastion --install-tools` installs whatever's missing — Go tools into your
GOPATH (no privilege), apt/pipx packages via `sudo`. Bastion **never handles
your sudo password**: privileged steps run `sudo <cmd>` so sudo prompts you on
its own terminal; the tool only ever builds the command line. Add `--dry-run` to
see the exact commands first.

## Web control panel

`bastion --web` launches a localhost control panel (stdlib only, no new
dependencies) to configure settings and keys, launch scans, and watch leads
stream in live over SSE, with the HTML/JSON report downloadable at the end. It
binds to 127.0.0.1 and embeds a per-session access token. The CLI remains the
primary interface for hands-on use.

## Usage

```
bastion example.com                                   # black-box passive, terminal
bastion example.com --ndjson | jq 'select(.priority > 8)'
bastion example.com --active --scope scope.txt
bastion example.com --active --scope scope.txt --nuclei
bastion example.com --active --scope scope.txt --bearer "$TOKEN"   # grey-box
bastion example.com --llm --brief
bastion example.com --active --scope scope.txt --html report.html
bastion example.com --json report.json
```

Terminal is the default surface. `--ndjson` emits one lead per line for
piping. `--html` writes a shareable report whose fort plan colours each wall by
the best impact reachable there, dashes it open where the wall is breached, and
drives assault arrows inward at the top avenues.

## Install

```
pipx install .          # or: pip install -e .
```

Recon-source keys via env: `SHODAN_API_KEY`, `CENSYS_PAT` (or
`CENSYS_API_ID`/`CENSYS_API_SECRET`), `SECURITYTRAILS_API_KEY`, `VT_API_KEY`,
`URLSCAN_API_KEY`, `RECORDED_FUTURE_API_KEY`. Bastion runs without any of them,
using crt.sh and DNS.

## Responsible use

For authorised engagements only. Active mode is gated behind an explicit scope
file for a reason: run it only against assets you are permitted to test.
