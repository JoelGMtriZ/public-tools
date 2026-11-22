"""Configuration, scope control, and credentials.

Two kinds of credential live here and must not be confused:
  * Recon-source keys (Shodan, Censys, ...) — the scout's own kit. Always used.
  * Target credentials (cookie, bearer, basic) — what promotes a run from
    black-box to grey-box, unlocking authenticated-surface collectors.

Scope is a bug-bounty-style include/exclude list on disk. Active collectors
validate every destination against it before a packet moves.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

from .models import Knowledge, Target, TargetKind


@dataclass(frozen=True)
class RateLimit:
    per_second: float
    burst: int = 1


RATE_LIMITS: dict[str, RateLimit] = {
    "crtsh":          RateLimit(0.5, 1),
    "shodan":         RateLimit(1.0, 1),
    "censys":         RateLimit(0.4, 1),
    "securitytrails": RateLimit(2.0, 2),
    "virustotal":     RateLimit(0.066, 1),
    "urlscan":        RateLimit(2.0, 2),
    "recordedfuture": RateLimit(5.0, 5),
    "wayback":        RateLimit(2.0, 2),
    "dns":            RateLimit(50.0, 50),
}

CACHE_TTL: dict[str, int] = {
    "crtsh": 6 * 3600, "shodan": 24 * 3600, "censys": 24 * 3600,
    "securitytrails": 24 * 3600, "virustotal": 24 * 3600, "urlscan": 12 * 3600,
    "recordedfuture": 6 * 3600, "wayback": 24 * 3600, "dns": 900,
}


@dataclass
class Credentials:
    """Recon-source API keys — the scout's own kit."""
    shodan: str | None = None
    censys_id: str | None = None
    censys_secret: str | None = None
    censys_token: str | None = None
    securitytrails: str | None = None
    virustotal: str | None = None
    urlscan: str | None = None
    recordedfuture: str | None = None

    @classmethod
    def from_env(cls) -> "Credentials":
        g = os.environ.get
        return cls(
            shodan=g("SHODAN_API_KEY"),
            censys_id=g("CENSYS_API_ID"),
            censys_secret=g("CENSYS_API_SECRET"),
            censys_token=g("CENSYS_PAT"),
            securitytrails=g("SECURITYTRAILS_API_KEY"),
            virustotal=g("VT_API_KEY") or g("VIRUSTOTAL_API_KEY"),
            urlscan=g("URLSCAN_API_KEY"),
            recordedfuture=g("RECORDED_FUTURE_API_KEY") or g("RF_TOKEN"),
        )

    def have(self, source: str) -> bool:
        return {
            "crtsh": True, "dns": True, "wayback": True,
            "shodan": bool(self.shodan),
            "censys": bool(self.censys_token or (self.censys_id and self.censys_secret)),
            "securitytrails": bool(self.securitytrails),
            "virustotal": bool(self.virustotal),
            "urlscan": bool(self.urlscan),
            "recordedfuture": bool(self.recordedfuture),
        }.get(source, False)


@dataclass
class TargetCreds:
    """Credentials *for the target*. Presence flips a run to grey-box."""
    cookie: str | None = None
    bearer: str | None = None
    basic: tuple[str, str] | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def present(self) -> bool:
        return bool(self.cookie or self.bearer or self.basic or self.headers)

    def as_headers(self) -> dict[str, str]:
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        return h

    @property
    def knowledge(self) -> Knowledge:
        return Knowledge.GREY if self.present else Knowledge.BLACK


class ScopeError(RuntimeError):
    """Raised when an active probe would leave the authorised scope."""


@dataclass
class Scope:
    """Authorised targets, bug-bounty style: includes plus out-of-scope excludes.

    File format, one entry per line, '#' comments, '!' prefix for exclusions:
        *.example.com
        example.com
        203.0.113.0/24
        !admin.example.com      # explicitly out of scope
        !192.0.2.0/24
    Wildcards are matched against hostnames with fnmatch.
    """
    include_domains: list[str] = field(default_factory=list)
    include_nets: list[ipaddress._BaseNetwork] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_nets: list[ipaddress._BaseNetwork] = field(default_factory=list)
    source_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope file not found: {p}")
        sc = cls(source_path=p)
        for lineno, line in enumerate(p.read_text().splitlines(), 1):
            entry = line.split("#", 1)[0].strip().lower()
            if not entry:
                continue
            exclude = entry.startswith("!")
            entry = entry.lstrip("!").strip()
            dom_list = sc.exclude_domains if exclude else sc.include_domains
            net_list = sc.exclude_nets if exclude else sc.include_nets
            try:
                if "/" in entry:
                    net_list.append(ipaddress.ip_network(entry, strict=False))
                else:
                    try:
                        addr = ipaddress.ip_address(entry)
                        net_list.append(ipaddress.ip_network(
                            f"{addr}/{'32' if addr.version == 4 else '128'}"))
                    except ValueError:
                        dom_list.append(entry)
            except ValueError as exc:
                raise ScopeError(f"{p}:{lineno}: {exc}") from exc
        if not (sc.include_domains or sc.include_nets):
            raise ScopeError(f"scope file {p} has no in-scope entries")
        return sc

    @staticmethod
    def _dom_match(host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            return host == pattern[2:] or host.endswith(pattern[1:])
        return host == pattern or host.endswith("." + pattern)

    def permits_host(self, host: str) -> bool:
        h = host.strip().lower().rstrip(".")
        try:
            addr = ipaddress.ip_address(h)
            if any(addr in n for n in self.exclude_nets):
                return False
            return any(addr in n for n in self.include_nets)
        except ValueError:
            if any(self._dom_match(h, p) for p in self.exclude_domains):
                return False
            return any(self._dom_match(h, p) for p in self.include_domains)

    def permits_target(self, target: Target) -> bool:
        if target.kind == TargetKind.DOMAIN:
            return self.permits_host(target.value)
        net = ipaddress.ip_network(target.value, strict=False)
        if any(net.overlaps(n) for n in self.exclude_nets):
            return False
        return any(net.subnet_of(n) for n in self.include_nets
                   if n.version == net.version)

    def assert_host(self, host: str) -> None:
        if not self.permits_host(host):
            raise ScopeError(
                f"{host} is not in authorised scope ({self.source_path}). "
                "Refusing to probe.")


@dataclass
class LLMConfig:
    """Attack-path synthesis via an OpenAI-compatible endpoint. Off by default."""
    enabled: bool = False
    base_url: str = "http://localhost:11434/v1"   # Ollama default
    model: str = "qwen3:8b"
    api_key: str = "not-needed"
    timeout: float = 120.0
    max_tokens: int = 1200
    temperature: float = 0.2
    tier: str = "small"

    @classmethod
    def from_env(cls) -> "LLMConfig":
        g = os.environ.get
        return cls(
            base_url=g("BASTION_LLM_URL", "http://localhost:11434/v1"),
            model=g("BASTION_LLM_MODEL", "qwen3:8b"),
            api_key=g("BASTION_LLM_KEY", "not-needed"),
        )



@dataclass(frozen=True)
class ScanProfile:
    """Timing/breadth profile for active work.

    Controls our own async collectors and the flags we hand orchestrated tools
    (naabu rate, nmap -T, nuclei rate). Stealth trades completeness and speed
    for a low, jittered footprint; aggressive does the opposite.
    """
    name: str
    concurrency: int
    ports: str            # "top100" | "top1000" | "full"
    connect_rate: int     # packets/sec hint for naabu/masscan
    connect_timeout: float
    http_timeout: float
    nuclei_rate: int
    nuclei_severities: str
    jitter_ms: int        # random per-probe delay (stealth)
    nmap_timing: str
    randomize: bool


SCAN_PROFILES = {
    "stealth": ScanProfile("stealth", concurrency=8, ports="top100",
                           connect_rate=50, connect_timeout=4.0, http_timeout=25.0,
                           nuclei_rate=20, nuclei_severities="medium,high,critical",
                           jitter_ms=250, nmap_timing="-T1", randomize=True),
    "balanced": ScanProfile("balanced", concurrency=64, ports="top1000",
                            connect_rate=500, connect_timeout=2.5, http_timeout=20.0,
                            nuclei_rate=150, nuclei_severities="low,medium,high,critical",
                            jitter_ms=0, nmap_timing="-T3", randomize=True),
    "aggressive": ScanProfile("aggressive", concurrency=300, ports="full",
                              connect_rate=2000, connect_timeout=1.2, http_timeout=12.0,
                              nuclei_rate=500, nuclei_severities="info,low,medium,high,critical",
                              jitter_ms=0, nmap_timing="-T4", randomize=False),
}
DEFAULT_PROFILE = "balanced"

@dataclass
class Config:
    creds: Credentials = field(default_factory=Credentials.from_env)
    target_creds: TargetCreds = field(default_factory=TargetCreds)
    cache_path: Path = Path("./bastion.sqlite")
    concurrency: int = 64
    http_timeout: float = 20.0
    scope: Scope | None = None
    allow_active: bool = False
    offline: bool = False   # disable all internet recon sources
    profile: ScanProfile = field(default_factory=lambda: SCAN_PROFILES[DEFAULT_PROFILE])
    rf_authorized: bool = False   # explicit ack for proximity/RF recon
    keys_path: Path = Path('~/.config/bastion/keys.env').expanduser()
    run_nuclei: bool = False
    max_expanded_hosts: int = 4096
    user_agent: str = "bastion/0.2"
    llm: LLMConfig = field(default_factory=LLMConfig.from_env)

    @property
    def knowledge(self) -> Knowledge:
        return self.target_creds.knowledge

    def enabled_sources(self) -> list[str]:
        return [s for s in RATE_LIMITS if self.creds.have(s)]
