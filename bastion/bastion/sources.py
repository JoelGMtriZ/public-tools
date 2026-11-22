"""Passive collectors.

Every collector here learns about the target from a third party. None of them
send traffic to the target itself, with one documented caveat in DnsCollector.

All of these are network-bound and rate-limit-bound, which is why they are
plain async Python rather than shelled-out binaries: a Go tool waits on
Shodan's 1 req/sec exactly as long as we do, and we get the raw response
objects for free.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import re
from datetime import datetime, timezone

from .models import (AssetKind, Mode, Observation, TargetKind, service_key)
from .registry import Collector, RunContext, register

log = logging.getLogger("bastion.sources")

_WILDCARD = re.compile(r"^\*\.")


def _clean_host(name: str) -> str | None:
    h = _WILDCARD.sub("", name.strip().lower().rstrip("."))
    if not h or " " in h or h.startswith("."):
        return None
    return h


def _ts(value) -> datetime | None:
    """Best-effort parse of the many timestamp shapes these APIs return."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, ValueError):
            return None
    s = str(value).replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Certificate transparency
# ---------------------------------------------------------------------------
@register
class CrtShCollector(Collector):
    name = "crtsh"
    mode = Mode.PASSIVE
    stage = 0
    provides = "subdomains and issuer history from certificate transparency logs"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.target.kind is TargetKind.DOMAIN

    async def run(self, ctx: RunContext) -> list[Observation]:
        domain = ctx.target.value
        rows = await ctx.http.get_json(
            self.name, "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            cache_key=f"crtsh:{domain}",
        )
        if not rows:
            return []

        obs: list[Observation] = []
        issuers: dict[str, int] = {}
        seen: set[str] = set()
        for row in rows:
            issued = _ts(row.get("not_before"))
            expires = _ts(row.get("not_after"))
            issuer = (row.get("issuer_name") or "").strip()
            if issuer:
                issuers[issuer] = issuers.get(issuer, 0) + 1
            for raw in (row.get("name_value") or "").split("\n"):
                host = _clean_host(raw)
                if not host or not host.endswith(domain) or host in seen:
                    continue
                seen.add(host)
                # A cert whose validity has lapsed suggests a host that may be
                # decommissioned, or may be quietly serving an expired cert.
                obs.append(Observation(
                    AssetKind.HOST, host,
                    attrs={"discovered_via": ["ct-log"],
                           "ct_last_issued": issued.isoformat() if issued else None,
                           "ct_expires": expires.isoformat() if expires else None,
                           "wildcard_cert": raw.strip().startswith("*.")},
                    evidence=self.evidence(
                        f"CT log entry, issuer {issuer[:60]}",
                        url=f"https://crt.sh/?q={host}",
                        data_timestamp=issued),
                ))

        if issuers:
            obs.append(Observation(
                AssetKind.DOMAIN, domain,
                attrs={"ct_issuers": sorted(issuers, key=issuers.get, reverse=True)[:10],
                       "ct_cert_count": len(rows)},
                evidence=self.evidence(f"{len(rows)} certificates in CT"),
            ))
        return obs


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
@register
class DnsCollector(Collector):
    """Resolve discovered names and read the domain's public DNS posture.

    Caveat on 'passive': recursive resolution ultimately reaches the target's
    authoritative nameservers. We query public recursive resolvers rather than
    the authoritative servers directly, so the target sees the resolver's
    address and not yours, and cache hits mean many queries never leave the
    resolver at all. That is as passive as name resolution gets.
    """
    name = "dns"
    mode = Mode.PASSIVE
    stage = 2          # runs after name-discovery sources
    provides = "live/dead status, A/AAAA, CNAME chains, MX, NS, SPF and DMARC"

    RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    async def run(self, ctx: RunContext) -> list[Observation]:
        try:
            import dns.asyncresolver
            import dns.resolver
        except ImportError:
            log.warning("dnspython not installed; skipping DNS stage")
            return []

        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = self.RESOLVERS
        resolver.timeout, resolver.lifetime = 3.0, 6.0

        obs: list[Observation] = []
        hosts = set(ctx.known_hosts)
        if ctx.target.kind is TargetKind.DOMAIN:
            hosts.add(ctx.target.value)
            obs.extend(await self._zone_posture(resolver, ctx.target.value))
            wildcard_ips = await self._wildcard_ips(resolver, ctx.target.value)
        else:
            wildcard_ips = set()

        sem = asyncio.Semaphore(min(ctx.cfg.concurrency, 100))

        async def resolve(host: str) -> None:
            async with sem:
                a = await self._query(resolver, host, "A")
                aaaa = await self._query(resolver, host, "AAAA")
                cname = await self._query(resolver, host, "CNAME")
                ips = a + aaaa
                if not ips and not cname:
                    obs.append(Observation(
                        AssetKind.HOST, host, attrs={"resolves": False},
                        evidence=self.evidence("NXDOMAIN or no address records")))
                    return
                # A name resolving only to the wildcard answer is not a real host.
                is_wildcard = bool(ips) and set(ips).issubset(wildcard_ips)
                obs.append(Observation(
                    AssetKind.HOST, host,
                    attrs={"resolves": True, "addresses": ips,
                           "cname": cname[0] if cname else None,
                           "wildcard_artifact": is_wildcard},
                    related=ips,
                    evidence=self.evidence(f"resolved to {len(ips)} address(es)")))
                if cname and not any(cname[0].endswith(s) for s in ("", )) is None:
                    pass
                for ip in ips:
                    if is_wildcard:
                        continue
                    obs.append(Observation(
                        AssetKind.IP, ip, attrs={"hostnames": [host]},
                        related=[host],
                        evidence=self.evidence(f"forward resolution of {host}")))

        await asyncio.gather(*(resolve(h) for h in sorted(hosts)))
        return obs

    async def _query(self, resolver, name: str, rdtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, rdtype)
            return [r.to_text().rstrip(".") for r in answer]
        except Exception:
            return []

    async def _wildcard_ips(self, resolver, domain: str) -> set[str]:
        """Probe three random labels; anything they all answer with is wildcard."""
        import secrets
        results = await asyncio.gather(*(
            self._query(resolver, f"{secrets.token_hex(8)}.{domain}", "A")
            for _ in range(3)))
        sets = [set(r) for r in results if r]
        if len(sets) < 2:
            return set()
        common = set.intersection(*sets)
        if common:
            log.info("wildcard DNS detected for %s -> %s", domain, sorted(common))
        return common

    async def _zone_posture(self, resolver, domain: str) -> list[Observation]:
        mx = await self._query(resolver, domain, "MX")
        ns = await self._query(resolver, domain, "NS")
        txt = await self._query(resolver, domain, "TXT")
        dmarc = await self._query(resolver, f"_dmarc.{domain}", "TXT")
        spf = [t for t in txt if "v=spf1" in t.lower()]
        return [Observation(
            AssetKind.DOMAIN, domain,
            attrs={"mx": mx, "ns": ns, "spf": spf, "dmarc": dmarc,
                   "txt_records": txt},
            evidence=self.evidence("zone apex records"),
        )]


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------
@register
class ShodanCollector(Collector):
    name = "shodan"
    mode = Mode.PASSIVE
    stage = 1
    provides = "open ports, service banners, product versions, observed TLS"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.creds.have("shodan")

    async def run(self, ctx: RunContext) -> list[Observation]:
        key = ctx.cfg.creds.shodan
        obs: list[Observation] = []
        if ctx.target.kind is TargetKind.DOMAIN:
            data = await ctx.http.get_json(
                self.name, f"https://api.shodan.io/dns/domain/{ctx.target.value}",
                params={"key": key})
            for rec in (data or {}).get("data", []) if isinstance(data, dict) else []:
                sub = rec.get("subdomain")
                host = f"{sub}.{ctx.target.value}" if sub else ctx.target.value
                obs.append(Observation(
                    AssetKind.HOST, host,
                    attrs={"discovered_via": ["shodan-dns"]},
                    evidence=self.evidence("Shodan passive DNS",
                                           data_timestamp=_ts(rec.get("last_seen")))))
            return obs

        for ip in ctx.target.hosts(ctx.cfg.max_expanded_hosts):
            obs.extend(await self._host(ctx, ip, key))
        return obs

    async def _host(self, ctx: RunContext, ip: str, key: str) -> list[Observation]:
        data = await ctx.http.get_json(
            self.name, f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key, "minify": "false"})
        if not isinstance(data, dict) or not data.get("data"):
            return []
        obs = [Observation(
            AssetKind.IP, ip,
            attrs={"asn": data.get("asn"), "org": data.get("org"),
                   "isp": data.get("isp"), "country": data.get("country_name"),
                   "hostnames": data.get("hostnames") or [],
                   "shodan_tags": data.get("tags") or []},
            evidence=self.evidence("Shodan host record"))]

        for svc in data["data"]:
            port, proto = svc.get("port"), svc.get("transport", "tcp")
            if not port:
                continue
            ssl_info = svc.get("ssl") or {}
            cert = ssl_info.get("cert") or {}
            obs.append(Observation(
                AssetKind.SERVICE, service_key(ip, port, proto),
                attrs={
                    "ip": ip, "port": port, "proto": proto,
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "service": svc.get("_shodan", {}).get("module"),
                    "cpe": svc.get("cpe23") or svc.get("cpe") or [],
                    "banner_excerpt": (svc.get("data") or "")[:400],
                    "http_title": (svc.get("http") or {}).get("title"),
                    "http_server": (svc.get("http") or {}).get("server"),
                    "tls_versions": [v for v, ok in
                                     (ssl_info.get("versions") and
                                      [(x.lstrip("-"), not x.startswith("-"))
                                       for x in ssl_info["versions"]] or [])
                                     if ok],
                    "tls_ciphers": ([ssl_info["cipher"].get("name")]
                                    if ssl_info.get("cipher") else []),
                    "cert_expired": cert.get("expired"),
                    "cert_issuer": (cert.get("issuer") or {}).get("CN"),
                    "cert_subject": (cert.get("subject") or {}).get("CN"),
                    "vulns": list((svc.get("vulns") or {}).keys()),
                },
                related=[ip],
                evidence=self.evidence(
                    f"Shodan banner on {port}/{proto}",
                    data_timestamp=_ts(svc.get("timestamp")))))
        return obs


# ---------------------------------------------------------------------------
# Censys
# ---------------------------------------------------------------------------
@register
class CensysCollector(Collector):
    name = "censys"
    mode = Mode.PASSIVE
    stage = 1
    provides = "second opinion on open services, TLS details and certificate chains"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.creds.have("censys")

    async def run(self, ctx: RunContext) -> list[Observation]:
        c = ctx.cfg.creds
        auth = (c.censys_id, c.censys_secret) if c.censys_id else None
        headers = {"Authorization": f"Bearer {c.censys_token}"} if c.censys_token else None

        if ctx.target.kind is TargetKind.DOMAIN:
            query = f"services.tls.certificates.leaf_data.subject_dn: {ctx.target.value}"
        elif ctx.target.kind is TargetKind.CIDR:
            query = f"ip: {ctx.target.value}"
        else:
            query = f"ip: {ctx.target.value}"

        data = await ctx.http.get_json(
            self.name, "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": 100},
            auth=auth, headers=headers, cache_key=f"censys:{query}")
        hits = ((data or {}).get("result") or {}).get("hits") or []

        obs: list[Observation] = []
        for hit in hits:
            ip = hit.get("ip")
            if not ip:
                continue
            loc = hit.get("location") or {}
            asn = hit.get("autonomous_system") or {}
            obs.append(Observation(
                AssetKind.IP, ip,
                attrs={"asn": asn.get("asn"), "org": asn.get("name"),
                       "country": loc.get("country"),
                       "hostnames": hit.get("dns", {}).get("names", [])},
                evidence=self.evidence("Censys host record")))
            for svc in hit.get("services", []):
                port = svc.get("port")
                if not port:
                    continue
                tls = svc.get("tls") or {}
                leaf = ((tls.get("certificates") or {}).get("leaf_data") or {})
                obs.append(Observation(
                    AssetKind.SERVICE,
                    service_key(ip, port, svc.get("transport_protocol", "tcp").lower()),
                    attrs={"ip": ip, "port": port,
                           "service": svc.get("service_name"),
                           "product": (svc.get("software") or [{}])[0].get("product"),
                           "version": (svc.get("software") or [{}])[0].get("version"),
                           "tls_versions": [tls.get("version_selected")] if tls else [],
                           "tls_ciphers": [tls.get("cipher_selected")] if tls else [],
                           "cert_issuer": (leaf.get("issuer") or {}).get("common_name"),
                           "cert_subject": (leaf.get("subject") or {}).get("common_name"),
                           },
                    related=[ip],
                    evidence=self.evidence(f"Censys service on {port}",
                                           data_timestamp=_ts(svc.get("observed_at")))))
        return obs


# ---------------------------------------------------------------------------
# SecurityTrails / VirusTotal / urlscan — name discovery
# ---------------------------------------------------------------------------
@register
class SecurityTrailsCollector(Collector):
    name = "securitytrails"
    mode = Mode.PASSIVE
    stage = 0
    provides = "historical subdomain inventory and passive DNS"

    def applicable(self, ctx: RunContext) -> bool:
        return (ctx.target.kind is TargetKind.DOMAIN
                and ctx.cfg.creds.have("securitytrails"))

    async def run(self, ctx: RunContext) -> list[Observation]:
        d = ctx.target.value
        data = await ctx.http.get_json(
            self.name, f"https://api.securitytrails.com/v1/domain/{d}/subdomains",
            params={"children_only": "false"},
            headers={"APIKEY": ctx.cfg.creds.securitytrails})
        subs = (data or {}).get("subdomains") or []
        return [Observation(
            AssetKind.HOST, f"{s}.{d}",
            attrs={"discovered_via": ["securitytrails"]},
            evidence=self.evidence("SecurityTrails subdomain inventory"))
            for s in subs if _clean_host(f"{s}.{d}")]


@register
class VirusTotalCollector(Collector):
    name = "virustotal"
    mode = Mode.PASSIVE
    stage = 0
    provides = "subdomains plus reputation verdicts on the estate"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.creds.have("virustotal")

    async def run(self, ctx: RunContext) -> list[Observation]:
        h = {"x-apikey": ctx.cfg.creds.virustotal}
        if ctx.target.kind is not TargetKind.DOMAIN:
            return await self._ip_reputation(ctx, h)

        d = ctx.target.value
        data = await ctx.http.get_json(
            self.name, f"https://www.virustotal.com/api/v3/domains/{d}/subdomains",
            params={"limit": 1000}, headers=h)
        obs = []
        for item in (data or {}).get("data", []):
            host = _clean_host(item.get("id", ""))
            if not host:
                continue
            stats = (item.get("attributes") or {}).get("last_analysis_stats") or {}
            obs.append(Observation(
                AssetKind.HOST, host,
                attrs={"discovered_via": ["virustotal"],
                       "vt_malicious": stats.get("malicious", 0),
                       "vt_suspicious": stats.get("suspicious", 0)},
                evidence=self.evidence("VirusTotal relations")))
        return obs

    async def _ip_reputation(self, ctx: RunContext, headers) -> list[Observation]:
        obs = []
        for ip in ctx.target.hosts(min(ctx.cfg.max_expanded_hosts, 256)):
            data = await ctx.http.get_json(
                self.name, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers)
            attrs = ((data or {}).get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            if not stats:
                continue
            obs.append(Observation(
                AssetKind.IP, ip,
                attrs={"vt_malicious": stats.get("malicious", 0),
                       "vt_suspicious": stats.get("suspicious", 0),
                       "asn": attrs.get("asn"), "org": attrs.get("as_owner")},
                evidence=self.evidence("VirusTotal IP reputation")))
        return obs


@register
class UrlscanCollector(Collector):
    name = "urlscan"
    mode = Mode.PASSIVE
    stage = 0
    provides = "hostnames, resolved IPs and page technologies from prior public scans"

    def applicable(self, ctx: RunContext) -> bool:
        return (ctx.target.kind is TargetKind.DOMAIN
                and ctx.cfg.creds.have("urlscan"))

    async def run(self, ctx: RunContext) -> list[Observation]:
        d = ctx.target.value
        data = await ctx.http.get_json(
            self.name, "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{d}", "size": 1000},
            headers={"API-Key": ctx.cfg.creds.urlscan})
        obs: list[Observation] = []
        for r in (data or {}).get("results", []):
            page = r.get("page") or {}
            host = _clean_host(page.get("domain", ""))
            if not host:
                continue
            obs.append(Observation(
                AssetKind.HOST, host,
                attrs={"discovered_via": ["urlscan"],
                       "server_header": page.get("server"),
                       "observed_ip": page.get("ip")},
                related=[page["ip"]] if page.get("ip") else [],
                evidence=self.evidence(
                    "urlscan.io prior scan",
                    url=r.get("result"),
                    data_timestamp=_ts((r.get("task") or {}).get("time")))))
            if page.get("server"):
                obs.append(Observation(
                    AssetKind.TECH, f"tech:{page['server']}",
                    attrs={"name": page["server"], "category": "web-server",
                           "hosts": [host]},
                    related=[host],
                    evidence=self.evidence("Server header seen by urlscan")))
        return obs


# ---------------------------------------------------------------------------
# Recorded Future — the outward-facing view
# ---------------------------------------------------------------------------
@register
class RecordedFutureCollector(Collector):
    """Threat intel on the estate itself.

    This is the only source that answers 'is this fort already known to the
    people outside it' — risk scores, appearance on infrastructure risk lists,
    and credential exposure. Everything else here describes the walls; this
    describes the besiegers' notes.
    """
    name = "recordedfuture"
    mode = Mode.PASSIVE
    stage = 3          # runs last, over everything the other stages found
    provides = "risk scores, risk-rule hits and exposure intel on discovered assets"

    #: Cap enrichment so a large estate does not burn the whole quota.
    MAX_ENRICH = 120

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.creds.have("recordedfuture")

    async def run(self, ctx: RunContext) -> list[Observation]:
        headers = {"X-RFToken": ctx.cfg.creds.recordedfuture,
                   "Accept": "application/json"}
        obs: list[Observation] = []

        ips = sorted(ctx.known_ips)[: self.MAX_ENRICH]
        hosts = sorted(ctx.known_hosts)[: self.MAX_ENRICH]
        if ctx.target.kind is TargetKind.DOMAIN:
            hosts = [ctx.target.value] + [h for h in hosts if h != ctx.target.value]

        sem = asyncio.Semaphore(8)

        async def enrich(kind: str, value: str, asset_kind: AssetKind) -> None:
            async with sem:
                data = await ctx.http.get_json(
                    self.name, f"https://api.recordedfuture.com/v2/{kind}/{value}",
                    params={"fields": "risk,intelCard,timestamps"}, headers=headers)
            payload = (data or {}).get("data") or {}
            risk = payload.get("risk") or {}
            score = risk.get("score")
            if score is None:
                return
            rules = [e.get("rule") for e in (risk.get("evidenceDetails") or [])
                     if e.get("rule")]
            obs.append(Observation(
                asset_kind, value,
                attrs={"rf_score": score,
                       "rf_level": risk.get("criticalityLabel"),
                       "rf_rules": rules,
                       "rf_rule_count": risk.get("riskString")},
                evidence=self.evidence(
                    f"Recorded Future risk {score} ({risk.get('criticalityLabel')})",
                    url=(payload.get("intelCard") or None))))

        await asyncio.gather(
            *(enrich("ip", ip, AssetKind.IP) for ip in ips),
            *(enrich("domain", h, AssetKind.HOST) for h in hosts),
        )
        return obs
