"""Core data model for Bastion — an offensive reconnaissance mapper.

The scout does not grade the castle. The scout hands the general a map marked
*hit here*. So the interpretive output is not a defensive posture score; it is a
set of LEADS (attackable observations, rated by what they yield and how
confirmed they are) organised into AVENUES OF APPROACH (ranked routes in).

Everything a collector learns becomes an Observation. Observations fold into
Assets. Assets are then read for Leads, and Leads assembled into Avenues.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Mode(str, Enum):
    """Whether a collector puts packets on the target."""
    PASSIVE = "passive"
    ACTIVE = "active"


class Knowledge(str, Enum):
    """Operator's starting access.

    Recon-source keys (Shodan, Censys, ...) are the scout's own kit, available
    in either box. GREY specifically means we hold *target* credentials — a
    session cookie, bearer token, or basic-auth pair — that unlock
    authenticated-surface collectors.
    """
    BLACK = "black"
    GREY = "grey"


class TargetKind(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class AssetKind(str, Enum):
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    NETBLOCK = "netblock"
    ASN = "asn"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    CERT = "cert"
    TECH = "tech"
    CREDENTIAL = "credential"


class Zone(str, Enum):
    """Fortification zones, read from the attacker's side of the wall."""
    CURTAIN_WALL = "curtain_wall"
    GATEHOUSE = "gatehouse"
    ARMORY = "armory"
    BANNERS = "banners"
    GARRISON = "garrison"
    POSTERN = "postern"
    KEEP = "keep"
    SALLYPORT = "sallyport"
    SCOUTS_REPORT = "scouts_report"
    ENVIRONS = "environs"


PLAN_ZONES = [
    Zone.CURTAIN_WALL, Zone.GATEHOUSE, Zone.ARMORY,
    Zone.GARRISON, Zone.BANNERS, Zone.POSTERN,
]

ZONE_LABEL = {
    Zone.CURTAIN_WALL: "Curtain Wall", Zone.GATEHOUSE: "Gatehouse",
    Zone.ARMORY: "Armory", Zone.BANNERS: "Banners",
    Zone.GARRISON: "Garrison", Zone.POSTERN: "Postern Gates",
    Zone.KEEP: "The Keep", Zone.SALLYPORT: "Sally Port",
    Zone.SCOUTS_REPORT: "Scout's Report",
    Zone.ENVIRONS: "The Environs",
}

ZONE_INTENT = {
    Zone.CURTAIN_WALL: "Get behind the edge — find origin the CDN/WAF is hiding",
    Zone.GATEHOUSE: "Attack the locks — auth surfaces to spray, bypass or abuse",
    Zone.ARMORY: "Break the crypto — downgrade, decrypt, or impersonate",
    Zone.BANNERS: "Read the colours — versions that tell you what to throw",
    Zone.GARRISON: "Storm a service — exposed daemons with known holes",
    Zone.POSTERN: "Slip the side door — forgotten or mis-scoped hosts",
    Zone.KEEP: "The objective — origin and core assets everything else guards",
    Zone.SALLYPORT: "Turn their own gates — SSRF, callbacks, redirects reaching inward",
    Zone.SCOUTS_REPORT: "Ground intelligence — leaks, exposure, prior compromise",
    Zone.ENVIRONS: "The surrounding field — devices in physical/RF proximity",
}


class Impact(int, Enum):
    """What an attacker gains if the lead pans out. Drives ranking."""
    RECON = 0
    DATA = 1
    FOOTHOLD = 2
    CREDENTIALS = 3
    TAKEOVER = 4
    RCE = 5

    @property
    def label(self) -> str:
        return {"RECON": "Recon", "DATA": "Data", "FOOTHOLD": "Foothold",
                "CREDENTIALS": "Creds", "TAKEOVER": "Takeover",
                "RCE": "RCE"}[self.name]


class Exploitability(int, Enum):
    """How real the lead is — likelihood it works, not its impact."""
    THEORETICAL = 0
    POSSIBLE = 1
    LIKELY = 2
    CONFIRMED = 3

    @property
    def label(self) -> str:
        return self.name.title()


_IMPACT_W = {Impact.RECON: 1, Impact.DATA: 3, Impact.FOOTHOLD: 5,
             Impact.CREDENTIALS: 6, Impact.TAKEOVER: 7, Impact.RCE: 9}
_EXPLOIT_W = {Exploitability.THEORETICAL: 0.4, Exploitability.POSSIBLE: 1.0,
              Exploitability.LIKELY: 2.0, Exploitability.CONFIRMED: 3.0}


class Confidence(str, Enum):
    REPORTED = "reported"
    CORROBORATED = "corroborated"
    OBSERVED = "observed"


@dataclass(frozen=True)
class Evidence:
    source: str
    observed_at: datetime
    detail: str = ""
    url: str | None = None
    data_timestamp: datetime | None = None

    def staleness_days(self) -> float | None:
        if self.data_timestamp is None:
            return None
        return (utcnow() - self.data_timestamp).total_seconds() / 86400.0


@dataclass
class Observation:
    asset_kind: AssetKind
    asset_key: str
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: Evidence | None = None
    related: list[str] = field(default_factory=list)


@dataclass
class Asset:
    kind: AssetKind
    key: str
    attrs: dict[str, Any] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)
    related: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    cluster: int | None = None
    anomaly_score: float | None = None

    @property
    def confidence(self) -> Confidence:
        if any(e.source.startswith("active:") for e in self.evidence):
            return Confidence.OBSERVED
        return Confidence.CORROBORATED if len(self.sources) > 1 else Confidence.REPORTED

    def merge(self, obs: "Observation") -> None:
        for k, v in obs.attrs.items():
            if v in (None, "", [], {}):
                continue
            existing = self.attrs.get(k)
            if existing is None:
                self.attrs[k] = v
            elif isinstance(existing, list) and isinstance(v, list):
                seen = {repr(x) for x in existing}
                existing.extend(x for x in v if repr(x) not in seen)
        if obs.evidence:
            self.evidence.append(obs.evidence)
            self.sources.add(obs.evidence.source)
            self.last_seen = max(self.last_seen, obs.evidence.observed_at)
        self.related.update(obs.related)


@dataclass
class Lead:
    """An attackable observation: what it is, what it yields, and the next move."""
    zone: Zone
    title: str
    asset_key: str
    impact: Impact
    exploitability: Exploitability
    move: str = ""
    detail: str = ""
    confidence: Confidence = Confidence.REPORTED
    source_tool: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = f"{self.zone.value}|{self.asset_key}|{self.title}"

    @property
    def priority(self) -> float:
        return round(_IMPACT_W[self.impact] * _EXPLOIT_W[self.exploitability], 2)

    @property
    def tag(self) -> str:
        return f"{self.impact.label}/{self.exploitability.label}"


@dataclass
class Avenue:
    """A ranked route in — one or more leads chaining toward an objective."""
    name: str
    entry_zone: Zone
    objective: str
    leads: list[Lead] = field(default_factory=list)
    narrative: str = ""
    llm_written: bool = False

    @property
    def score(self) -> float:
        if not self.leads:
            return 0.0
        best = max(l.priority for l in self.leads)
        return round(best + 0.5 * (len(self.leads) - 1), 2)

    @property
    def best_impact(self) -> Impact:
        return max((l.impact for l in self.leads), default=Impact.RECON)


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    value: str

    @property
    def is_network(self) -> bool:
        return self.kind in (TargetKind.IP, TargetKind.CIDR)

    def hosts(self, cap: int = 4096) -> list[str]:
        if self.kind == TargetKind.IP:
            return [self.value]
        if self.kind == TargetKind.CIDR:
            net = ipaddress.ip_network(self.value, strict=False)
            out = []
            for i, ip in enumerate(net.hosts()):
                if i >= cap:
                    break
                out.append(str(ip))
            return out
        return []


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def parse_target(raw: str) -> Target:
    """Accept a domain, IP, CIDR, or a URL to strip down to its host."""
    s = raw.strip().lower().rstrip(".")
    if not s:
        raise ValueError("empty target")
    if s.startswith(("http://", "https://")):
        s = re.sub(r"^https?://", "", s).split("/")[0].split(":")[0]
    if "/" in s:
        try:
            return Target(TargetKind.CIDR,
                          str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            s = s.split("/")[0]
    try:
        return Target(TargetKind.IP, str(ipaddress.ip_address(s)))
    except ValueError:
        pass
    if _DOMAIN_RE.match(s):
        return Target(TargetKind.DOMAIN, s)
    raise ValueError(f"not a domain, IP, or CIDR: {raw!r}")


def service_key(ip: str, port: int, proto: str = "tcp") -> str:
    return f"{ip}:{port}/{proto}"
