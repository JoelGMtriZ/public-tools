"""Raw ClientHello TLS prober.

Why this exists: Python's stdlib `ssl` is bound to the system OpenSSL, and
OpenSSL 3.x refuses to negotiate SSLv3 and commonly gates TLS 1.0/1.1 behind
the security-level floor. A stdlib-based scan therefore returns FALSE NEGATIVES
on exactly the obsolete-protocol findings we want. `sslscan` ships a bundled
legacy OpenSSL to dodge this; we dodge it differently — by writing the
ClientHello bytes ourselves over a plain socket and reading the ServerHello.
That bypasses OpenSSL policy entirely, is fully async, and needs no subprocess.

We do not complete a handshake. We send one ClientHello offering a single
protocol version and a broad cipher list, then read the server's first record:
  * ServerHello (0x02) with a chosen version  -> that version is supported
  * Alert (record type 0x15)                  -> refused / not supported
  * nothing / reset                           -> not supported
This is enough to enumerate which protocol versions a listener will speak.
"""
from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import dataclass, field

# TLS record/protocol version wire values.
VERSIONS = {
    "SSLv3":   0x0300,
    "TLSv1.0": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    # TLS 1.3 pins the record version to 0x0303 and negotiates via an
    # extension; handled specially below.
    "TLSv1.3": 0x0304,
}

OBSOLETE = {"SSLv3", "TLSv1.0", "TLSv1.1"}

# A spread of cipher suites old and new, so a legacy server finds something it
# likes. Values are IANA suite ids.
_CIPHERS = [
    0x1301, 0x1302, 0x1303,                    # TLS 1.3
    0xc02f, 0xc030, 0xc02b, 0xc02c,            # ECDHE AES-GCM
    0xc027, 0xc013, 0xc014,                    # ECDHE AES-CBC
    0x009c, 0x009d, 0x002f, 0x0035,            # RSA AES
    0xc012, 0x000a,                            # 3DES
    0x0005, 0x0004,                            # RC4
]


@dataclass
class TlsResult:
    host: str
    port: int
    supported: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def obsolete(self) -> list[str]:
        return [v for v in self.supported if v in OBSOLETE]


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _build_client_hello(version_name: str, sni: str | None) -> bytes:
    is_13 = version_name == "TLSv1.3"
    # record + legacy handshake version: keep at TLS 1.0 for the record, and set
    # the ClientHello legacy_version to the offered version (0x0303 for 1.3).
    legacy_ver = 0x0303 if is_13 else VERSIONS[version_name]

    rand = os.urandom(32)
    session_id = os.urandom(32)                # non-empty; 1.3 servers expect it
    ciphers = b"".join(struct.pack(">H", c) for c in _CIPHERS)
    comp = b"\x01\x00"                          # length 1, null compression

    exts = b""
    if sni:
        name = sni.encode("idna") if all(ord(c) < 128 for c in sni) else sni.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name    # type host_name
        exts += _ext(0x0000, struct.pack(">H", len(entry)) + entry)

    # supported_groups: x25519, secp256r1, secp384r1
    groups = [0x001d, 0x0017, 0x0018]
    gb = b"".join(struct.pack(">H", g) for g in groups)
    exts += _ext(0x000a, struct.pack(">H", len(gb)) + gb)
    # ec_point_formats: uncompressed
    exts += _ext(0x000b, b"\x01\x00")
    # signature_algorithms
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
            0x0806, 0x0601, 0x0201]
    sb = b"".join(struct.pack(">H", s) for s in sigs)
    exts += _ext(0x000d, struct.pack(">H", len(sb)) + sb)
    # renegotiation_info (empty) — some middleboxes want it
    exts += _ext(0xff01, b"\x00")

    if is_13:
        # supported_versions: offer only TLS 1.3 so acceptance is unambiguous.
        exts += _ext(0x002b, b"\x02\x03\x04")
        # key_share: one x25519 (group 0x001d) entry, 32-byte public value.
        pub = os.urandom(32)
        entry = struct.pack(">HH", 0x001d, len(pub)) + pub
        exts += _ext(0x0033, struct.pack(">H", len(entry)) + entry)

    body = struct.pack(">H", legacy_ver) + rand
    body += struct.pack(">B", len(session_id)) + session_id
    body += struct.pack(">H", len(ciphers)) + ciphers
    body += comp
    body += struct.pack(">H", len(exts)) + exts

    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16" + struct.pack(">H", 0x0301) + \
        struct.pack(">H", len(handshake)) + handshake
    return record


async def _offer(host: str, port: int, version_name: str, sni: str | None,
                 timeout: float) -> str | None:
    """Return the negotiated version name if the server accepts, else None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(_build_client_hello(version_name, sni))
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
        rec_type, rec_ver, rec_len = struct.unpack(">BHH", head)
        if rec_type == 0x15:            # Alert => refused
            return None
        if rec_type != 0x16:            # not a handshake
            return None
        payload = await asyncio.wait_for(
            reader.readexactly(min(rec_len, 2048)), timeout=timeout)
        if not payload or payload[0] != 0x02:   # not a ServerHello
            return None
        # ServerHello: legacy_version at body offset 4..6.
        if len(payload) < 6:
            return None
        chosen = struct.unpack(">H", payload[4:6])[0]
        # TLS 1.3 reports 0x0303 here and signals 1.3 via supported_versions;
        # since we offered only 1.3, acceptance is sufficient to confirm it.
        if version_name == "TLSv1.3":
            return "TLSv1.3"
        for nm, val in VERSIONS.items():
            if val == chosen:
                return nm
        return version_name
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def probe(host: str, port: int = 443, *, sni: str | None = None,
                timeout: float = 6.0) -> TlsResult:
    """Enumerate which protocol versions a TLS listener will negotiate."""
    sni = sni or (host if not host.replace(".", "").isdigit() else None)
    res = TlsResult(host=host, port=port)
    order = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]
    outcomes = await asyncio.gather(
        *(_offer(host, port, v, sni, timeout) for v in order))
    for got in outcomes:
        if got and got not in res.supported:
            res.supported.append(got)
    res.supported.sort(key=lambda v: list(VERSIONS).index(v))
    if not res.supported:
        res.error = "no version negotiated (host may not speak TLS on this port)"
    return res
