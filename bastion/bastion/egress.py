"""Self-describing egress map.

Bastion knows every remote endpoint it can reach, so it can print its own
firewall allowlist rather than making the operator guess. Use this when running
inside a network where outbound must be opened deliberately:

    bastion --egress                 # human-readable, grouped by purpose
    bastion --egress --json          # machine-readable for automation

Endpoints are grouped by when they are needed (one-time setup vs. per-run) and
by whether they are only reached when a given feature/key is enabled, so an
operator can open the minimum.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .config import Config


@dataclass
class Endpoint:
    host: str
    port: int
    purpose: str
    phase: str                 # "setup" | "runtime"
    condition: str = "always"  # when this is actually contacted
    protocol: str = "https"


# --- setup / installation (one-time) ---------------------------------------
SETUP_ENDPOINTS = [
    Endpoint("pypi.org", 443, "install the Python package", "setup",
             "if installing via pip/pipx"),
    Endpoint("files.pythonhosted.org", 443, "download Python wheels", "setup",
             "if installing via pip/pipx"),
    Endpoint("github.com", 443, "install/update ProjectDiscovery tools & nuclei templates",
             "setup", "if fetching scanners or templates"),
    Endpoint("raw.githubusercontent.com", 443, "nuclei template updates", "setup",
             "if using nuclei"),
    Endpoint("api.github.com", 443, "release metadata for tool installers", "setup",
             "if installing scanners via their installers"),
    # local LLM bootstrap
    Endpoint("ollama.com", 443, "Ollama install script & model index", "setup",
             "only with --llm-setup"),
    Endpoint("registry.ollama.ai", 443, "pull local model weights", "setup",
             "only with --llm-setup"),
]

# --- passive recon sources (per-run, only if that source is enabled) --------
SOURCE_ENDPOINTS = {
    "crtsh":          Endpoint("crt.sh", 443, "certificate transparency search", "runtime"),
    "dns":            Endpoint("<your DNS resolver>", 53, "DNS resolution", "runtime",
                               "always (use internal resolvers for internal targets)",
                               protocol="dns"),
    "shodan":         Endpoint("api.shodan.io", 443, "host/service intel", "runtime",
                               "if SHODAN_API_KEY set"),
    "censys":         Endpoint("search.censys.io", 443, "host/cert intel", "runtime",
                               "if Censys creds set"),
    "securitytrails": Endpoint("api.securitytrails.com", 443, "DNS history/subdomains",
                               "runtime", "if SECURITYTRAILS_API_KEY set"),
    "virustotal":     Endpoint("www.virustotal.com", 443, "domain/IP relations", "runtime",
                               "if VT_API_KEY set"),
    "urlscan":        Endpoint("urlscan.io", 443, "historical scans/subdomains", "runtime",
                               "if URLSCAN_API_KEY set"),
    "recordedfuture": Endpoint("api.recordedfuture.com", 443, "risk intel", "runtime",
                               "if RECORDED_FUTURE_API_KEY set"),
    "wayback":        Endpoint("web.archive.org", 443, "historical URLs/endpoints",
                               "runtime", "if endpoint discovery enabled"),
}


def collect_endpoints(cfg: Config | None = None, *, include_setup: bool = True,
                      only_enabled: bool = False) -> list[Endpoint]:
    eps: list[Endpoint] = []
    if include_setup:
        eps += SETUP_ENDPOINTS
    for name, ep in SOURCE_ENDPOINTS.items():
        if only_enabled and cfg is not None:
            if name in ("crtsh", "dns", "wayback"):
                pass  # no key required
            elif not cfg.creds.have(name):
                continue
        eps.append(ep)
    # The LLM endpoint itself — local by default, but list it if remote.
    if cfg is not None and cfg.llm.base_url and "localhost" not in cfg.llm.base_url \
            and "127.0.0.1" not in cfg.llm.base_url:
        from urllib.parse import urlparse
        u = urlparse(cfg.llm.base_url)
        eps.append(Endpoint(u.hostname or cfg.llm.base_url, u.port or 443,
                            "remote LLM inference endpoint", "runtime",
                            "if --llm points at a remote endpoint"))
    return eps


def render_text(cfg: Config | None = None, *, only_enabled: bool = False) -> str:
    eps = collect_endpoints(cfg, only_enabled=only_enabled)
    L = ["Bastion — outbound endpoints to allow through the firewall",
         "=" * 62, "",
         "Bastion reaches targets directly (internet or internal) and, "
         "optionally,", "a set of third-party recon sources. Active scanning "
         "of targets uses", "whatever ports the target exposes and is bounded "
         "by your --scope file;", "the endpoints below are Bastion's own "
         "service dependencies only.", ""]
    for phase, title in [("setup", "ONE-TIME SETUP"), ("runtime", "PER-RUN")]:
        rows = [e for e in eps if e.phase == phase]
        if not rows:
            continue
        L.append(title)
        L.append("-" * len(title))
        for e in rows:
            L.append(f"  {e.protocol:>5}  {e.host:<28} :{e.port:<5} "
                     f"{e.purpose}")
            L.append(f"         └─ {e.condition}")
        L.append("")
    L.append("NOTES")
    L.append("-----")
    L.append("  • Fully offline / air-gapped internal engagements: run with "
             "--offline to")
    L.append("    disable every internet recon source. Bastion then talks only "
             "to your")
    L.append("    targets and your DNS resolver — nothing leaves the network.")
    L.append("  • For internal targets, point DNS at your internal resolvers; "
             "public")
    L.append("    sources (crt.sh, Shodan, ...) hold no data on RFC1918 space "
             "anyway.")
    L.append("  • The local LLM (Ollama) only needs egress during --llm-setup "
             "to pull")
    L.append("    weights; inference itself is entirely local afterward.")
    return "\n".join(L)


def render_json(cfg: Config | None = None, *, only_enabled: bool = False) -> str:
    eps = collect_endpoints(cfg, only_enabled=only_enabled)
    return json.dumps({
        "description": "Outbound endpoints Bastion may contact. Target traffic "
                       "is separate and bounded by --scope.",
        "offline_mode": "run with --offline to disable all internet sources",
        "endpoints": [{
            "host": e.host, "port": e.port, "protocol": e.protocol,
            "purpose": e.purpose, "phase": e.phase, "condition": e.condition,
        } for e in eps],
    }, indent=2)
