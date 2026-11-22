"""Active collectors — packets on the target. Gated by --active + scope.

On Kali/Parrot the offensive toolchain is present, so where a battle-tested
binary clearly wins we orchestrate it (naabu/masscan for SYN scans, nuclei for
templated checks, subfinder for extra free subdomain sources) and parse its
JSON. Where pure Python is competitive and gives us the response objects we
need, we do it ourselves (connect scan, the raw-ClientHello TLS prober, HTTP
fingerprinting). Each active collector calls ctx.assert_in_scope() per
destination before connecting.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone

import random
from .models import (AssetKind, Mode, Observation, TargetKind, service_key)
from .registry import Collector, RunContext, register
from .tlsprobe import probe as tls_probe

log = logging.getLogger("bastion.active")

# Ports worth a connect-scan when we have no port data from passive sources.
TOP_PORTS = [80, 443, 22, 21, 25, 8080, 8443, 8000, 3389, 3306, 5432, 6379,
             27017, 9200, 11211, 23, 445, 139, 135, 1433, 5900, 389, 636,
             161, 2375, 2379, 6443, 10000, 9090, 8888, 5000, 4443, 7001,
             8081, 9000, 3000, 5601, 15672, 1521, 5984]

# Stealth uses the 20 highest-value ports; balanced the full list; aggressive adds low ports
_PORTS_TOP100 = TOP_PORTS[:20]
_PORTS_FULL   = sorted(set(TOP_PORTS) | set(range(1, 1025)))

def _port_list(profile):
    if profile.ports == 'top100': return _PORTS_TOP100
    if profile.ports == 'full':   return _PORTS_FULL
    return TOP_PORTS  # top1000 default

async def _jitter(profile):
    if profile.jitter_ms > 0:
        await asyncio.sleep(random.uniform(0, profile.jitter_ms / 1000.0))



def _now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Port discovery
# ---------------------------------------------------------------------------
@register
class ConnectScanCollector(Collector):
    """Async TCP connect scan. Pure Python, no root needed.

    Prefers naabu when present (SYN scan, far faster and quieter); otherwise a
    tuned asyncio full-connect scan, which is usable to roughly a /22.
    """
    name = "portscan"
    mode = Mode.ACTIVE
    stage = 5
    provides = "open TCP ports on in-scope hosts"

    async def run(self, ctx: RunContext) -> list[Observation]:
        targets = self._targets(ctx)
        for t in targets:
            ctx.assert_in_scope(t)
        if not targets:
            return []
        if ctx.caps.has("naabu"):
            return await self._naabu(ctx, targets)
        return await self._asyncio_scan(ctx, targets)

    def _targets(self, ctx: RunContext) -> list[str]:
        if ctx.target.kind is TargetKind.DOMAIN:
            return sorted({ip for ip in ctx.known_ips}) or []
        return ctx.target.hosts(ctx.cfg.max_expanded_hosts)

    async def _naabu(self, ctx: RunContext, targets: list[str]) -> list[Observation]:
        profile = ctx.cfg.profile
        rate = str(profile.connect_rate)
        ports_flag = {"top100": "100", "top1000": "1000", "full": "65535"}.get(profile.ports, "1000")
        cmd = [ctx.caps.tools["naabu"], "-silent", "-json", "-rate", rate,
               "-top-ports", ports_flag]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate("\n".join(targets).encode())
        obs = []
        for line in out.decode(errors="ignore").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip, port = rec.get("ip") or rec.get("host"), rec.get("port")
            if ip and port:
                obs.append(Observation(
                    AssetKind.SERVICE, service_key(ip, port),
                    attrs={"ip": ip, "port": port, "proto": "tcp", "state": "open"},
                    related=[ip], evidence=self.evidence(f"naabu {port} open")))
        return obs

    async def _asyncio_scan(self, ctx: RunContext,
                            targets: list[str]) -> list[Observation]:
        profile = ctx.cfg.profile
        ports = _port_list(profile)
        sem = asyncio.Semaphore(min(profile.concurrency * 8, 800))
        obs: list[Observation] = []

        async def check(ip: str, port: int) -> None:
            if ctx.stopped():
                return
            await _jitter(profile)
            async with sem:
                try:
                    fut = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(
                        fut, timeout=profile.connect_timeout)
                except (OSError, asyncio.TimeoutError):
                    return
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                obs.append(Observation(
                    AssetKind.SERVICE, service_key(ip, port),
                    attrs={"ip": ip, "port": port, "proto": "tcp", "state": "open"},
                    related=[ip], evidence=self.evidence(f"connect {port} open")))

        await asyncio.gather(*(check(ip, p) for ip in targets for p in ports))
        return obs


# ---------------------------------------------------------------------------
# TLS enumeration via the raw prober
# ---------------------------------------------------------------------------
@register
class TlsProbeCollector(Collector):
    """Enumerate negotiated TLS versions with the raw-ClientHello prober.

    This is preferred over stdlib ssl precisely because it reports obsolete
    protocols the system OpenSSL would refuse to speak. sslscan is used as a
    cross-check when present."""
    name = "tlsprobe"
    mode = Mode.ACTIVE
    stage = 6
    provides = "negotiated TLS versions per listener, incl. legacy protocols"

    TLS_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990, 4443, 5061}

    async def run(self, ctx: RunContext) -> list[Observation]:
        # Candidate ip:port pairs from discovered services + common TLS ports.
        candidates: set[tuple[str, int]] = set()
        for ip in ctx.known_ips:
            for p in (443, 8443):
                candidates.add((ip, p))
        # Anything else discovered on a TLS-ish port also gets probed by the
        # pipeline via known service ports; here we keep it to the ip set.
        obs: list[Observation] = []
        sem = asyncio.Semaphore(min(ctx.cfg.profile.concurrency, 100))

        async def one(ip: str, port: int) -> None:
            ctx.assert_in_scope(ip)
            async with sem:
                res = await tls_probe(ip, port, timeout=ctx.cfg.profile.connect_timeout)
            if not res.supported:
                return
            obs.append(Observation(
                AssetKind.SERVICE, service_key(ip, port),
                attrs={"ip": ip, "port": port, "proto": "tcp",
                       "tls_versions": res.supported,
                       "tls_obsolete": res.obsolete},
                related=[ip],
                evidence=self.evidence(
                    f"raw ClientHello: {', '.join(res.supported)}")))

        await asyncio.gather(*(one(ip, p) for ip, p in candidates))
        return obs


# ---------------------------------------------------------------------------
# HTTP fingerprinting (grey-box aware)
# ---------------------------------------------------------------------------
@register
class HttpFingerprintCollector(Collector):
    """Fetch HTTP(S) on discovered hosts: status, server, title, tech hints.

    Sends target credentials when running grey-box, so authenticated surface
    and post-login redirects are captured. Prefers ProjectDiscovery httpx when
    present for speed and richer tech detection."""
    name = "httpfinger"
    mode = Mode.ACTIVE
    stage = 6
    provides = "HTTP status, headers, titles, tech, and endpoints (auth-aware in grey-box)"

    async def run(self, ctx: RunContext) -> list[Observation]:
        hosts = sorted(ctx.known_hosts) or (
            [ctx.target.value] if ctx.target.kind is TargetKind.DOMAIN else [])
        hosts += sorted(ctx.known_ips)
        for h in hosts:
            ctx.assert_in_scope(h)
        if not hosts:
            return []

        headers = ctx.cfg.target_creds.as_headers()
        grey = bool(headers)
        obs: list[Observation] = []
        sem = asyncio.Semaphore(min(ctx.cfg.profile.concurrency, 60))

        async def fetch(host: str) -> None:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                async with sem:
                    data = await ctx.http.get_json(
                        f"active:httpfinger", url, headers=headers or None,
                        expect_json=False, cache_key=f"httpfinger:{grey}:{url}",
                        ttl=0)
                if data is None:
                    continue
                # get_json returns text when expect_json=False
                title = _title(data) if isinstance(data, str) else None
                obs.append(Observation(
                    AssetKind.ENDPOINT, url,
                    attrs={"host": host, "scheme": scheme, "http_title": title,
                           "authenticated": grey,
                           "body_len": len(data) if isinstance(data, str) else None},
                    related=[host],
                    evidence=self.evidence(f"HTTP fetch {url}"
                                           + (" (authenticated)" if grey else ""))))
                break

        await asyncio.gather(*(fetch(h) for h in hosts))
        return obs


def _title(html: str) -> str | None:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:200] if m else None


# ---------------------------------------------------------------------------
# subfinder — extra free subdomain sources
# ---------------------------------------------------------------------------
@register
class SubfinderCollector(Collector):
    name = "subfinder"
    mode = Mode.ACTIVE          # active only in that it's opt-in; it's still passive-ish
    requires_tool = "subfinder"
    stage = 4
    provides = "additional subdomains from subfinder's source set"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.target.kind is TargetKind.DOMAIN

    async def run(self, ctx: RunContext) -> list[Observation]:
        d = ctx.target.value
        proc = await asyncio.create_subprocess_exec(
            ctx.caps.tools["subfinder"], "-silent", "-d", d,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        obs = []
        for line in out.decode(errors="ignore").splitlines():
            host = line.strip().lower()
            if host.endswith(d):
                ctx.assert_in_scope(host)
                obs.append(Observation(
                    AssetKind.HOST, host,
                    attrs={"discovered_via": ["subfinder"]},
                    evidence=self.evidence("subfinder")))
        return obs


# ---------------------------------------------------------------------------
# nuclei — templated vulnerability checks (only behind --nuclei)
# ---------------------------------------------------------------------------
@register
class NucleiCollector(Collector):
    """Run nuclei against discovered HTTP endpoints. The 'exploits' engine.

    Opt-in twice over: active mode, plus --nuclei, because it is the loudest
    thing Bastion does. Findings arrive already rated by nuclei severity; we
    translate them into confirmed Leads downstream. Grey-box adds auth headers
    so authenticated templates fire."""
    name = "nuclei"
    mode = Mode.ACTIVE
    requires_tool = "nuclei"
    stage = 8
    provides = "confirmed vulnerabilities and misconfigurations via nuclei templates"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.run_nuclei

    async def run(self, ctx: RunContext) -> list[Observation]:
        hosts = sorted(ctx.known_hosts) or (
            [ctx.target.value] if ctx.target.kind is TargetKind.DOMAIN else [])
        hosts += sorted(ctx.known_ips)
        targets = []
        for h in hosts:
            ctx.assert_in_scope(h)
            targets += [f"https://{h}", f"http://{h}"]
        if not targets:
            return []

        profile = ctx.cfg.profile
        cmd = [ctx.caps.tools["nuclei"], "-silent", "-jsonl", "-no-color",
               "-severity", profile.nuclei_severities,
               "-rate-limit", str(profile.nuclei_rate), "-timeout", "8"]
        for k, v in ctx.cfg.target_creds.as_headers().items():
            cmd += ["-H", f"{k}: {v}"]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate("\n".join(targets).encode())

        obs = []
        for line in out.decode(errors="ignore").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {})
            matched = r.get("matched-at") or r.get("host") or ""
            obs.append(Observation(
                AssetKind.ENDPOINT, matched or r.get("template-id", "nuclei"),
                attrs={"nuclei_template": r.get("template-id"),
                       "nuclei_name": info.get("name"),
                       "nuclei_severity": (info.get("severity") or "info").lower(),
                       "nuclei_tags": info.get("tags") or [],
                       "nuclei_refs": (info.get("reference") or []),
                       "nuclei_cves": [c.upper() for c in
                                       (info.get("classification", {}) or {})
                                       .get("cve-id", []) or []],
                       "matched_at": matched},
                evidence=self.evidence(
                    f"nuclei {r.get('template-id')} [{info.get('severity')}]",
                    url=matched)))
        return obs
