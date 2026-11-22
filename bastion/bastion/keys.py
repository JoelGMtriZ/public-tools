"""One key file to rule them all.

Bastion reads recon-source keys from the environment or a single `keys.env`
file, and can export them into the per-tool formats other binaries expect (e.g.
subfinder's provider-config.yaml). Keys are always optional — with none set,
Bastion still runs on crt.sh + DNS. The configurator only ever prompts for keys
the operator chooses to enter.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .config import Credentials

# canonical key name -> (env var, prompt label, which tools consume it)
KEY_SPECS = [
    ("SHODAN_API_KEY",         "Shodan API key",          ["bastion", "subfinder"]),
    ("CENSYS_PAT",             "Censys PAT",              ["bastion", "subfinder"]),
    ("CENSYS_API_ID",          "Censys API ID (legacy)",  ["bastion"]),
    ("CENSYS_API_SECRET",      "Censys API secret (legacy)", ["bastion"]),
    ("SECURITYTRAILS_API_KEY", "SecurityTrails API key",  ["bastion", "subfinder"]),
    ("VT_API_KEY",             "VirusTotal API key",      ["bastion", "subfinder"]),
    ("URLSCAN_API_KEY",        "urlscan.io API key",      ["bastion"]),
    ("RECORDED_FUTURE_API_KEY","Recorded Future token",   ["bastion"]),
    ("GITHUB_TOKEN",           "GitHub token (subfinder/gau)", ["subfinder"]),
]


def load_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def merge_into_environ(path: Path) -> int:
    """Load keys.env, letting real environment variables win. Returns count set."""
    n = 0
    for k, v in load_env_file(path).items():
        if v and not os.environ.get(k):
            os.environ[k] = v
            n += 1
    return n


def write_env_file(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Bastion recon-source keys. All optional.",
             "# Real environment variables override these at runtime.", ""]
    for name, label, _ in KEY_SPECS:
        v = values.get(name, "")
        lines.append(f"# {label}")
        lines.append(f"{name}={v}")
        lines.append("")
    path.write_text("\n".join(lines))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 0600 — secrets on disk


def configure_interactive(path: Path) -> None:
    """Prompt only for keys the operator wants to set; blank keeps existing."""
    print(f"\nConfiguring recon-source keys → {path}")
    print("All optional. Press Enter to skip a key (keeps any existing value).\n")
    existing = load_env_file(path)
    values = dict(existing)
    for name, label, tools in KEY_SPECS:
        cur = existing.get(name, "")
        shown = f" [set]" if cur else ""
        try:
            entry = input(f"  {label}{shown}: ").strip()
        except EOFError:
            break
        if entry:
            values[name] = entry
    write_env_file(path, values)
    n = sum(1 for v in values.values() if v)
    print(f"\nSaved {n} key(s) to {path} (mode 0600).")
    print("Run `bastion --export-keys` to push them into subfinder etc.")


def export_subfinder(path: Path, creds: Credentials | None = None,
                     env: dict[str, str] | None = None) -> Path:
    """Write subfinder's provider-config.yaml from our keys.

    Minimal YAML is emitted directly (no yaml dependency), which keeps the base
    install to two pure-Python packages.
    """
    env = env or {**load_env_file(path), **os.environ}
    dest = Path("~/.config/subfinder/provider-config.yaml").expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)

    def block(provider: str, *vals: str) -> list[str]:
        present = [v for v in vals if v]
        if not present:
            return []
        return [f"{provider}:"] + [f"  - {v}" for v in present]

    lines: list[str] = []
    lines += block("shodan", env.get("SHODAN_API_KEY", ""))
    # subfinder wants censys as "id:secret"
    cid, csec = env.get("CENSYS_API_ID", ""), env.get("CENSYS_API_SECRET", "")
    if cid and csec:
        lines += ["censys:", f"  - {cid}:{csec}"]
    lines += block("securitytrails", env.get("SECURITYTRAILS_API_KEY", ""))
    lines += block("virustotal", env.get("VT_API_KEY", ""))
    lines += block("github", env.get("GITHUB_TOKEN", ""))

    dest.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
    return dest


def status(path: Path, env: dict[str, str] | None = None) -> dict[str, bool]:
    env = env or {**load_env_file(path), **os.environ}
    return {name: bool(env.get(name)) for name, _, _ in KEY_SPECS}
