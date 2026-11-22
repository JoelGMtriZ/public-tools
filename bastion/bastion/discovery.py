"""LAN service discovery: mDNS/Bonjour (incl. AirPlay) and IP-camera recon.

These are network-native — they fit the existing scope model. mDNS is a real
multicast query built with the stdlib (no dependency); camera recon is service
fingerprinting over RTSP/ONVIF/known web UIs with default-credential *flagging*
(never brute-forcing).
"""
from __future__ import annotations

import asyncio
import socket
import struct

from .models import AssetKind, Mode, Observation, TargetKind, service_key
from .registry import Collector, RunContext, register

MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353

# Service types worth asking for. AirPlay + AirDrop-adjacent + common infra.
MDNS_SERVICES = [
    "_airplay._tcp.local", "_raop._tcp.local",       # AirPlay / AirPlay audio
    "_airdrop._tcp.local",                            # AirDrop (also needs AWDL)
    "_googlecast._tcp.local",                         # Chromecast
    "_spotify-connect._tcp.local",
    "_http._tcp.local", "_https._tcp.local",
    "_ssh._tcp.local", "_smb._tcp.local", "_afpovertcp._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local",
    "_rfb._tcp.local",                                # VNC
    "_workstation._tcp.local", "_device-info._tcp.local",
    "_hap._tcp.local",                                # HomeKit
    "_sonos._tcp.local", "_daap._tcp.local",
]


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _mdns_query(services: list[str]) -> bytes:
    # one query, multiple questions (PTR)
    header = struct.pack(">HHHHHH", 0, 0, len(services), 0, 0, 0)
    body = b""
    for svc in services:
        body += _encode_qname(svc) + struct.pack(">HH", 12, 1)  # PTR, IN
    return header + body


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    orig = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length & 0xC0 == 0xC0:            # compression pointer
            ptr = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                orig = offset + 2
            offset = ptr
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode(errors="ignore"))
        offset += 1 + length
    return ".".join(labels), (orig if jumped else offset)


@register
class MdnsCollector(Collector):
    """Discover Bonjour/mDNS services on the local segment (AirPlay, Chromecast,
    printers, SMB, VNC, HomeKit, ...). Sends a multicast query and listens."""
    name = "mdns"
    mode = Mode.ACTIVE
    stage = 5
    provides = "mDNS/Bonjour services on the local network (AirPlay, casts, printers)"

    def applicable(self, ctx: RunContext) -> bool:
        return True

    async def run(self, ctx: RunContext) -> list[Observation]:
        loop = asyncio.get_event_loop()
        try:
            responses = await asyncio.wait_for(
                loop.run_in_executor(None, self._query_blocking), 6.0)
        except (asyncio.TimeoutError, OSError):
            return []
        obs: list[Observation] = []
        for src_ip, ptrs in responses.items():
            for svc in ptrs:
                kind = _friendly(svc)
                obs.append(Observation(
                    AssetKind.SERVICE, f"mdns:{src_ip}:{svc}",
                    attrs={"ip": src_ip, "mdns_service": svc, "device_kind": kind},
                    related=[src_ip],
                    evidence=self.evidence(f"mDNS {kind or svc} at {src_ip}")))
        return obs

    def _query_blocking(self) -> dict[str, set]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(_mdns_query(MDNS_SERVICES), (MDNS_ADDR, MDNS_PORT))
        except OSError:
            sock.close()
            return {}
        found: dict[str, set] = {}
        import time
        deadline = time.time() + 4.0
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            names = self._extract_ptrs(data)
            if names:
                found.setdefault(addr[0], set()).update(names)
        sock.close()
        return found

    def _extract_ptrs(self, data: bytes) -> set:
        try:
            qd, an = struct.unpack(">H", data[4:6])[0], struct.unpack(">H", data[6:8])[0]
        except struct.error:
            return set()
        offset = 12
        for _ in range(qd):
            _, offset = _parse_name(data, offset)
            offset += 4
        names = set()
        for _ in range(an):
            _, offset = _parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 12:                    # PTR
                target, _ = _parse_name(data, offset)
                for svc in MDNS_SERVICES:
                    if svc in target or target.endswith(svc):
                        names.add(svc.replace(".local", "").lstrip("_"))
            offset += rdlen
        return names


def _friendly(svc: str) -> str:
    return {
        "airplay._tcp": "AirPlay receiver", "raop._tcp": "AirPlay audio",
        "airdrop._tcp": "AirDrop peer", "googlecast._tcp": "Chromecast",
        "hap._tcp": "HomeKit accessory", "rfb._tcp": "VNC server",
        "printer._tcp": "printer", "ipp._tcp": "printer",
        "smb._tcp": "SMB host", "sonos._tcp": "Sonos",
    }.get(svc, svc)


# --- IP camera recon -------------------------------------------------------
CAMERA_PORTS = {554: "RTSP", 8554: "RTSP-alt", 80: "HTTP", 443: "HTTPS",
                8000: "Hikvision-SDK", 37777: "Dahua", 2020: "ONVIF-alt",
                8899: "ONVIF", 88: "ONVIF-Hik"}

CAMERA_SIGNATURES = [
    ("hikvision", ["hikvision", "web components", "doc/page/login"]),
    ("dahua", ["dahua", "webplugin", "rpc2_loginflag"]),
    ("axis", ["axis", "vapix"]),
    ("reolink", ["reolink"]),
    ("dlink", ["dcs-", "d-link"]),
    ("foscam", ["foscam"]),
    ("ubiquiti", ["unifi video", "ubnt"]),
    ("generic-rtsp", ["rtsp/1.0", "live555", "streaming server"]),
]

# vendor -> commonly shipped default credential pairs (for FLAGGING only)
CAMERA_DEFAULTS = {
    "hikvision": ["admin:12345"], "dahua": ["admin:admin"],
    "axis": ["root:pass"], "reolink": ["admin:(blank)"],
    "dlink": ["admin:(blank)"], "foscam": ["admin:(blank)"],
    "ubiquiti": ["ubnt:ubnt"], "generic-rtsp": ["admin:admin", "admin:(blank)"],
}


@register
class CameraCollector(Collector):
    """Fingerprint IP cameras / NVRs by port + banner, and flag known default
    credentials for the identified vendor. Does not attempt logins."""
    name = "cctv"
    mode = Mode.ACTIVE
    stage = 7
    provides = "IP cameras/NVRs identified by vendor, with default-credential flags"

    def applicable(self, ctx: RunContext) -> bool:
        return True

    async def run(self, ctx: RunContext) -> list[Observation]:
        ips = sorted(ctx.known_ips) or (
            ctx.target.hosts(ctx.cfg.max_expanded_hosts)
            if ctx.target.kind in (TargetKind.IP, TargetKind.CIDR) else [])
        for ip in ips:
            ctx.assert_in_scope(ip)
        if not ips:
            return []
        obs: list[Observation] = []
        sem = asyncio.Semaphore(min(ctx.cfg.profile.concurrency, 100))

        async def probe(ip: str, port: int, label: str) -> None:
            async with sem:
                vendor, banner = await self._fingerprint(ip, port)
            if not vendor:
                return
            defaults = CAMERA_DEFAULTS.get(vendor, [])
            obs.append(Observation(
                AssetKind.SERVICE, service_key(ip, port),
                attrs={"ip": ip, "port": port, "proto": "tcp",
                       "device_kind": "IP camera / NVR", "camera_vendor": vendor,
                       "camera_protocol": label,
                       "default_creds": defaults, "product": f"{vendor} camera"},
                related=[ip], evidence=self.evidence(
                    f"{vendor} camera on {ip}:{port} ({label})")))

        tasks = [probe(ip, port, label) for ip in ips
                 for port, label in CAMERA_PORTS.items()]
        await asyncio.gather(*tasks)
        return obs

    async def _fingerprint(self, ip: str, port: int) -> tuple[str | None, str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0)
        except (OSError, asyncio.TimeoutError):
            return None, ""
        try:
            if port in (554, 8554):
                req = (f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\n"
                       "CSeq: 1\r\n\r\n").encode()
            else:
                req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
                       "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode()
            writer.write(req)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            text = data.decode(errors="ignore").lower()
        except (OSError, asyncio.TimeoutError):
            return None, ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        for vendor, needles in CAMERA_SIGNATURES:
            if any(n in text for n in needles):
                return vendor, text[:80]
        if port in (554, 8554) and "rtsp" in text:
            return "generic-rtsp", text[:80]
        return None, ""
