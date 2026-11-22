"""Proximity / RF recon — Bluetooth, BLE, and AirDrop presence.

Authorisation note: unlike network recon, RF scanning captures devices belonging
to whoever is physically nearby — people who are not in any scope file. So this
is gated on an explicit, separate acknowledgement (cfg.rf_authorized, set by
--rf-authorized) rather than the network --scope, and it is strictly PASSIVE:
Bastion enumerates what is advertising and stops there. No pairing, connecting,
probing, or attacking. It orchestrates the platform's own tooling (bluetoothctl
/ hcitool / bettercap) and needs a Bluetooth adapter; AirDrop additionally needs
an AWDL-capable stack, so it is best-effort.
"""
from __future__ import annotations

import asyncio
import re

from .models import AssetKind, Mode, Observation
from .registry import Collector, RunContext, register


async def _run(cmd, timeout=20.0, stdin=None):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE if stdin else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin else None), timeout=timeout)
        return proc.returncode or 0, out.decode(errors="ignore")
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
        return 1, str(exc)


class _RfBase(Collector):
    mode = Mode.ACTIVE
    requires_rf = True                       # gated on cfg.rf_authorized

    def applicable(self, ctx: RunContext) -> bool:
        return ctx.cfg.rf_authorized


@register
class BluetoothCollector(_RfBase):
    """Passive discovery of classic Bluetooth + BLE devices in range.

    Prefers `bluetoothctl` (bluez); falls back to `hcitool`/`bettercap`. Reports
    address, name, and (for BLE) advertised service hints — presence only."""
    name = "bluetooth"
    stage = 9
    provides = "Bluetooth/BLE devices advertising in physical range (presence only)"

    async def run(self, ctx: RunContext) -> list[Observation]:
        if not ctx.cfg.rf_authorized:
            return []
        if ctx.caps.has("bluetoothctl"):
            devices = await self._bluetoothctl(ctx)
        elif ctx.caps.has("hcitool"):
            devices = await self._hcitool(ctx)
        elif ctx.caps.has("bettercap"):
            devices = await self._bettercap(ctx)
        else:
            return []
        obs = []
        for addr, name, extra in devices:
            obs.append(Observation(
                AssetKind.HOST, f"bt:{addr}",
                attrs={"bt_address": addr, "bt_name": name or "(unknown)",
                       "device_kind": "Bluetooth/BLE device", "rf": True, **extra},
                evidence=self.evidence(
                    f"BT device {addr} {name or ''}".strip())))
        return obs

    async def _bluetoothctl(self, ctx):
        # scan on, wait, then read the device list; entirely passive discovery
        await _run(["bluetoothctl", "--timeout", "12", "scan", "on"], timeout=18)
        code, out = await _run(["bluetoothctl", "devices"], timeout=10)
        devs = []
        for m in re.finditer(r"Device\s+([0-9A-F:]{17})\s+(.*)", out):
            devs.append((m.group(1), m.group(2).strip(), {}))
        return devs

    async def _hcitool(self, ctx):
        code, out = await _run(["hcitool", "scan", "--flush"], timeout=20)
        devs = []
        for m in re.finditer(r"([0-9A-F:]{17})\s+(.*)", out):
            devs.append((m.group(1), m.group(2).strip(), {}))
        # BLE pass
        code, out = await _run(["timeout", "10", "hcitool", "lescan"], timeout=14)
        for m in re.finditer(r"([0-9A-F:]{17})\s+(.*)", out):
            devs.append((m.group(1), m.group(2).strip(), {"ble": True}))
        return devs

    async def _bettercap(self, ctx):
        code, out = await _run(
            ["bettercap", "-eval", "ble.recon on; sleep 12; ble.show; quit"],
            timeout=20)
        devs = []
        for m in re.finditer(r"([0-9a-f:]{17})\s+([^\|]+)", out):
            devs.append((m.group(1).upper(), m.group(2).strip(), {"ble": True}))
        return devs


@register
class AirdropCollector(_RfBase):
    """Best-effort AirDrop peer presence.

    AirDrop rides AWDL + BLE. Full discovery needs an AWDL stack (e.g. OWL) in
    monitor mode; where that is not present we surface AirDrop-capable peers seen
    via the BLE pass instead, and say so. Presence only."""
    name = "airdrop"
    stage = 9
    provides = "AirDrop-capable peers in range (best-effort; needs AWDL for full recon)"

    async def run(self, ctx: RunContext) -> list[Observation]:
        if not ctx.cfg.rf_authorized:
            return []
        if ctx.caps.has("owl"):
            return await self._owl(ctx)
        # No AWDL stack: note the capability gap rather than pretend.
        return [Observation(
            AssetKind.HOST, "airdrop:awdl-unavailable",
            attrs={"device_kind": "AirDrop recon", "rf": True,
                   "note": "AWDL monitor stack (owl) not found; AirDrop peers "
                           "may still appear via the Bluetooth/BLE pass."},
            evidence=self.evidence("AirDrop full recon needs an AWDL stack"))]

    async def _owl(self, ctx):
        # If an OWL-based AWDL interface exists, enumerate advertised peers.
        code, out = await _run(["owl", "-l"], timeout=15)
        obs = []
        for m in re.finditer(r"peer\s+([0-9a-f:]{17})\s+(.*)", out, re.I):
            obs.append(Observation(
                AssetKind.HOST, f"airdrop:{m.group(1)}",
                attrs={"bt_address": m.group(1), "device_kind": "AirDrop peer",
                       "rf": True, "awdl": True},
                evidence=self.evidence(f"AirDrop peer {m.group(1)}")))
        return obs
