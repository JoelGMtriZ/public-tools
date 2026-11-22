# Network requirements

This file lists every outbound endpoint Bastion may contact, so you can open the minimum on an internal firewall. Generated from the tool itself — regenerate with `bastion --egress` (`--json` for machine-readable).

```
Bastion — outbound endpoints to allow through the firewall
==============================================================

Bastion reaches targets directly (internet or internal) and, optionally,
a set of third-party recon sources. Active scanning of targets uses
whatever ports the target exposes and is bounded by your --scope file;
the endpoints below are Bastion's own service dependencies only.

ONE-TIME SETUP
--------------
  https  pypi.org                     :443   install the Python package
         └─ if installing via pip/pipx
  https  files.pythonhosted.org       :443   download Python wheels
         └─ if installing via pip/pipx
  https  github.com                   :443   install/update ProjectDiscovery tools & nuclei templates
         └─ if fetching scanners or templates
  https  raw.githubusercontent.com    :443   nuclei template updates
         └─ if using nuclei
  https  api.github.com               :443   release metadata for tool installers
         └─ if installing scanners via their installers
  https  ollama.com                   :443   Ollama install script & model index
         └─ only with --llm-setup
  https  registry.ollama.ai           :443   pull local model weights
         └─ only with --llm-setup

PER-RUN
-------
  https  crt.sh                       :443   certificate transparency search
         └─ always
    dns  <your DNS resolver>          :53    DNS resolution
         └─ always (use internal resolvers for internal targets)
  https  api.shodan.io                :443   host/service intel
         └─ if SHODAN_API_KEY set
  https  search.censys.io             :443   host/cert intel
         └─ if Censys creds set
  https  api.securitytrails.com       :443   DNS history/subdomains
         └─ if SECURITYTRAILS_API_KEY set
  https  www.virustotal.com           :443   domain/IP relations
         └─ if VT_API_KEY set
  https  urlscan.io                   :443   historical scans/subdomains
         └─ if URLSCAN_API_KEY set
  https  api.recordedfuture.com       :443   risk intel
         └─ if RECORDED_FUTURE_API_KEY set
  https  web.archive.org              :443   historical URLs/endpoints
         └─ if endpoint discovery enabled

NOTES
-----
  • Fully offline / air-gapped internal engagements: run with --offline to
    disable every internet recon source. Bastion then talks only to your
    targets and your DNS resolver — nothing leaves the network.
  • For internal targets, point DNS at your internal resolvers; public
    sources (crt.sh, Shodan, ...) hold no data on RFC1918 space anyway.
  • The local LLM (Ollama) only needs egress during --llm-setup to pull
    weights; inference itself is entirely local afterward.
```

## Targets vs. dependencies

The endpoints above are Bastion's own service dependencies. Traffic to the targets you assess is separate: passive mode never touches them; active mode only contacts hosts your `--scope` permits. SMB, mDNS/AirPlay, camera, and RF recon talk to the target/local segment or the air around you — not to any of the endpoints above. For internal work use `--offline` so no third-party source is contacted at all.
