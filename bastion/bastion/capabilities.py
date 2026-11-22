"""Runtime capability detection.

Bastion has a pure-Python floor for every active technique, and prefers an
external binary only where the binary is genuinely better. This module decides
which path each stage takes, so the same code runs on a full pentest box and in
a locked-down sandbox with nothing but the interpreter.

Where binaries actually win:
  * Port scanning  — SYN scan via raw sockets is 10-100x a Python connect scan.
  * Legacy TLS     — see note in probes.py: the stdlib `ssl` module is bound to
                     the system OpenSSL, which refuses to negotiate SSLv2/v3 and
                     often TLS 1.0/1.1. That produces FALSE NEGATIVES on exactly
                     the findings we care about. sslscan ships a bundled legacy
                     OpenSSL. Our raw-ClientHello prober sidesteps the problem
                     entirely and is used as the primary; sslscan cross-checks.

Where they do not:
  * Anything API-driven. Wall time there is rate-limit wait, not compute.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

#: binary -> what we would use it for
KNOWN_TOOLS = {
    "naabu":     "fast SYN port discovery",
    "masscan":   "very large netblock port sweeps",
    "nmap":      "service/version fingerprinting and NSE",
    "sslscan":   "legacy TLS/cipher cross-check with bundled OpenSSL",
    "testssl.sh":"exhaustive TLS audit",
    "subfinder": "extra free subdomain sources beyond our own API keys",
    "amass":     "deep DNS enumeration and correlation",
    "dnsx":      "high-rate DNS resolution and record probing",
    "httpx":     "high-rate HTTP probing and tech detection",
    "nuclei":    "templated vulnerability and misconfiguration checks",
    "katana":    "crawling for endpoints and JS-referenced routes",
    "gau":       "historical URLs from Wayback/CommonCrawl/OTX",
    "waybackurls":"historical URLs from the Wayback Machine",
    "ffuf":      "content and vhost fuzzing",
    "netexec":   "SMB/AD enumeration (nxc, ex-crackmapexec)",
    "nxc":       "SMB/AD enumeration (netexec alias)",
    "crackmapexec":"SMB/AD enumeration (legacy)",
    "smbclient":  "SMB share listing and file retrieval",
    "enum4linux-ng":"deep SMB/host/user enumeration",
    "bluetoothctl":"Bluetooth/BLE discovery (bluez)",
    "hcitool":    "Bluetooth/BLE discovery (legacy bluez)",
    "bettercap":  "BLE/wireless recon framework",
    "owl":        "AWDL monitor stack for AirDrop recon",
}


@dataclass
class Capabilities:
    tools: dict[str, str] = field(default_factory=dict)   # name -> resolved path
    can_raw_socket: bool = False
    openssl_version: str = ""
    #: True when the linked OpenSSL will not speak legacy protocols, meaning
    #: stdlib-based TLS probing cannot be trusted for negative results.
    stdlib_tls_is_restricted: bool = True

    def has(self, name: str) -> bool:
        return name in self.tools

    def summary(self) -> list[str]:
        lines = []
        for name, why in KNOWN_TOOLS.items():
            mark = "+" if self.has(name) else "-"
            lines.append(f"  [{mark}] {name:<11} {why}")
        lines.append(f"  raw sockets: {'yes' if self.can_raw_socket else 'no (SYN scan unavailable)'}")
        lines.append(f"  openssl:     {self.openssl_version}")
        if self.stdlib_tls_is_restricted:
            lines.append("  note:        stdlib TLS cannot test legacy protocols; "
                         "using raw ClientHello prober")
        return lines


def _probe_openssl() -> tuple[str, bool]:
    try:
        import ssl
        version = ssl.OPENSSL_VERSION
    except Exception:
        return "unknown", True
    restricted = True
    try:
        import ssl as _ssl
        # If the constants for legacy protocols are absent or the default
        # context refuses to lower its minimum, we cannot test legacy support.
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = _ssl.TLSVersion.TLSv1
        restricted = ctx.minimum_version != _ssl.TLSVersion.TLSv1
    except Exception:
        restricted = True
    # OpenSSL 3.x drops SSLv3 and gates TLS1.0/1.1 behind security level 0
    if version.startswith("OpenSSL 3"):
        restricted = True
    return version, restricted


def _can_raw_socket() -> bool:
    if os.geteuid() == 0:
        return True
    # Linux capability check without requiring the `capng` module.
    try:
        out = subprocess.run(["capsh", "--print"], capture_output=True,
                             text=True, timeout=3).stdout
        return "cap_net_raw" in out
    except Exception:
        return False


def detect() -> Capabilities:
    caps = Capabilities()
    for name in KNOWN_TOOLS:
        path = shutil.which(name)
        if path:
            caps.tools[name] = path
    caps.can_raw_socket = _can_raw_socket()
    caps.openssl_version, caps.stdlib_tls_is_restricted = _probe_openssl()
    return caps
