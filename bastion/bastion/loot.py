"""Credential & secret hunting over discovered files.

Used against readable SMB shares (and reusable elsewhere). Design constraints
for an authorised engagement: read-only, never exfiltrate the secret value —
report its *type and location* with a redacted preview so an operator can go
retrieve it deliberately. File reads are size-capped and binary is skipped.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

MAX_FILE_BYTES = 2_000_000          # skip anything larger; loot lives in small files
ENTROPY_MIN_LEN = 20

# name -> (compiled regex, human label, whether it's high-signal)
# name -> (regex, label, high_signal, value_group)  value_group None => whole match
_PATTERNS = {
    "aws_access_key":   (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id", True, None),
    "aws_secret":       (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "AWS secret key", True, 1),
    "private_key":      (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key file", True, None),
    "gcp_key":          (re.compile(r'"type"\s*:\s*"service_account"'), "GCP service-account key", True, None),
    "azure_secret":     (re.compile(r"(?i)(?:client_secret|AccountKey)\s*[=:]\s*['\"]?([A-Za-z0-9/+=_.-]{20,})"), "Azure/API secret", True, 1),
    "slack_token":      (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token", True, None),
    "github_pat":       (re.compile(r"\bghp_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "GitHub token", True, None),
    "jwt":              (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT", False, None),
    "generic_api_key":  (re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=_.-]{16,})"), "generic API key/secret", False, 1),
    "password_assign":  (re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{6,})"), "hardcoded password", False, 1),
    "conn_string":      (re.compile(r"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|ftp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"), "connection string with creds", True, None),
}

# Files most worth reading first when a share is huge.
INTERESTING_NAMES = re.compile(
    r"(?i)(passw|cred|secret|\.env$|config|settings|\.ya?ml$|\.ini$|\.conf$|"
    r"\.ps1$|\.bat$|\.sh$|unattend|sysprep|web\.config|\.kdbx$|\.pem$|\.ppk$|"
    r"id_rsa|\.git-credentials|backup|dump|\.sql$|\.bak$)")


@dataclass
class Secret:
    kind: str
    label: str
    location: str
    preview: str
    line: int = 0
    high_signal: bool = True


def _redact(value: str) -> str:
    value = value.strip().strip("'\"")
    if len(value) <= 8:
        return value[0] + "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_text(text: str, location: str, *, entropy: bool = True) -> list[Secret]:
    found: list[Secret] = []
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 4000:
            line = line[:4000]
        for kind, (rx, label, hi, vg) in _PATTERNS.items():
            m = rx.search(line)
            if not m:
                continue
            key = (kind, i)
            if key in seen:
                continue
            seen.add(key)
            val = m.group(vg) if vg else m.group(0)
            found.append(Secret(kind, label, location, _redact(val), i, hi))
        if entropy:
            for tok in re.findall(r"[A-Za-z0-9/+=_-]{%d,}" % ENTROPY_MIN_LEN, line):
                if _shannon(tok) >= 4.0 and not any(
                        s.line == i for s in found):
                    found.append(Secret("high_entropy",
                                        "high-entropy string (possible secret)",
                                        location, _redact(tok), i, False))
                    break
    return found


def scan_bytes(data: bytes, location: str) -> list[Secret]:
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    if b"\x00" in data[:1024]:            # crude binary guard
        return []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return []
    return scan_text(text, location)


def worth_reading(filename: str) -> bool:
    return bool(INTERESTING_NAMES.search(filename))
