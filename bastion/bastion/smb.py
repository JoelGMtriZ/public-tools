"""SMB enumeration and share looting for IP and CIDR targets.

Flow: find 445/tcp -> enumerate shares (netexec, else smbclient) -> for readable
shares, list files and read the interesting, small ones -> run the loot scanner
for creds/keys. Read-only throughout; we report where secrets live, redacted,
never exfiltrate them. Scope-gated per host like every active collector.
"""
from __future__ import annotations

import asyncio
import json
import re

from .loot import scan_bytes, worth_reading
from .models import AssetKind, Mode, Observation, TargetKind, service_key
from .registry import Collector, RunContext, register

SHARE_SKIP = {"print$", "IPC$"}


async def _run(cmd: list[str], timeout: float = 120.0) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out.decode(errors="ignore")
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
        return 1, str(exc)


@register
class SmbEnumCollector(Collector):
    """Enumerate SMB shares, then loot readable ones for credentials.

    Prefers netexec (nxc/crackmapexec), falls back to smbclient. enum4linux-ng
    is used for richer host/user enumeration when available."""
    name = "smb"
    mode = Mode.ACTIVE
    stage = 7
    provides = "SMB shares, readability, and credentials/keys found in readable shares"

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.target.kind in (TargetKind.IP, TargetKind.CIDR) or bool(ctx.known_ips)

    def _hosts(self, ctx: RunContext) -> list[str]:
        if ctx.target.kind is TargetKind.CIDR:
            hosts = ctx.target.hosts(ctx.cfg.max_expanded_hosts)
        elif ctx.target.kind is TargetKind.IP:
            hosts = [ctx.target.value]
        else:
            hosts = sorted(ctx.known_ips)
        # only hosts we already saw 445 on, if we have that data; else all
        with_smb = {s.attrs.get("ip") for s in []}  # placeholder; graph not here
        return hosts

    async def run(self, ctx: RunContext) -> list[Observation]:
        hosts = self._hosts(ctx)
        for h in hosts:
            ctx.assert_in_scope(h)
        if not hosts:
            return []

        have_nxc = ctx.caps.has("netexec") or ctx.caps.has("nxc") or ctx.caps.has("crackmapexec")
        have_smbclient = ctx.caps.has("smbclient")
        if not (have_nxc or have_smbclient):
            return []   # registry emits a skip-note via requires_tool on subclasses

        obs: list[Observation] = []
        sem = asyncio.Semaphore(min(ctx.cfg.profile.concurrency, 20))

        async def one(host: str) -> None:
            async with sem:
                shares = await self._enum_shares(ctx, host, have_nxc, have_smbclient)
            if shares is None:
                return
            svc = service_key(host, 445)
            obs.append(Observation(
                AssetKind.SERVICE, svc,
                attrs={"ip": host, "port": 445, "proto": "tcp",
                       "product": "SMB", "smb_shares": [s["name"] for s in shares],
                       "smb_readable": [s["name"] for s in shares if s["readable"]]},
                related=[host], evidence=self.evidence(
                    f"SMB: {len(shares)} share(s), "
                    f"{sum(1 for s in shares if s['readable'])} readable")))
            for share in shares:
                if share["readable"] and share["name"] not in SHARE_SKIP:
                    await self._loot_share(ctx, host, share["name"], obs)

        await asyncio.gather(*(one(h) for h in hosts))
        return obs

    async def _enum_shares(self, ctx, host, have_nxc, have_smbclient):
        if have_nxc:
            tool = (ctx.caps.tools.get("netexec") or ctx.caps.tools.get("nxc")
                    or ctx.caps.tools.get("crackmapexec"))
            code, out = await _run([tool, "smb", host, "-u", "", "-p", "",
                                    "--shares"], timeout=90)
            if "445" not in out and "SMB" not in out:
                return None
            shares = []
            for m in re.finditer(
                    r"^\s*(\S+)\s+(READ|WRITE|READ,WRITE|READ, WRITE)?\s*(.*)$",
                    out, re.M):
                name = m.group(1)
                if name in ("SMB", "Share", "-----") or "." in name:
                    continue
                perms = (m.group(2) or "").upper()
                shares.append({"name": name, "readable": "READ" in perms,
                               "perms": perms})
            return shares or None
        # smbclient fallback: list shares anonymously
        tool = ctx.caps.tools["smbclient"]
        code, out = await _run([tool, "-N", "-L", f"//{host}"], timeout=60)
        if "NT_STATUS" in out and "Sharename" not in out:
            return None
        shares = []
        for m in re.finditer(r"^\s+(\S+)\s+Disk", out, re.M):
            name = m.group(1)
            if name in SHARE_SKIP:
                continue
            shares.append({"name": name, "readable": True, "perms": "?"})
        return shares or None

    async def _loot_share(self, ctx, host, share, obs: list) -> None:
        tool = ctx.caps.tools.get("smbclient")
        if not tool:
            return
        # recursive listing, then targeted reads of interesting small files
        code, out = await _run(
            [tool, "-N", f"//{host}/{share}", "-c", "recurse ON; ls"], timeout=90)
        files = re.findall(r"^\s+([^\s].*?)\s+[AHSRD]+\s+(\d+)\s+", out, re.M)
        for path, size in files[:200]:
            path = path.strip()
            if not worth_reading(path) or int(size) > 2_000_000:
                continue
            data = await self._read_file(tool, host, share, path)
            if not data:
                continue
            for sec in scan_bytes(data, f"//{host}/{share}/{path}"):
                obs.append(Observation(
                    AssetKind.CREDENTIAL, f"{host}:{share}:{path}:{sec.kind}",
                    attrs={"secret_kind": sec.kind, "label": sec.label,
                           "location": sec.location, "preview": sec.preview,
                           "high_signal": sec.high_signal, "host": host},
                    related=[host], evidence=self.evidence(
                        f"{sec.label} in {sec.location}")))

    async def _read_file(self, tool, host, share, path) -> bytes | None:
        import tempfile
        import os
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            code, _ = await _run(
                [tool, "-N", f"//{host}/{share}", "-c",
                 f'get "{path}" "{tmp.name}"'], timeout=45)
            with open(tmp.name, "rb") as fh:
                return fh.read(2_000_000)
        except OSError:
            return None
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
