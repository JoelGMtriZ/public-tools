"""Install missing tooling — without ever handling your sudo password.

Privileged steps are run as `sudo <cmd>`, so sudo does its OWN terminal prompt.
The password goes keyboard → sudo; Bastion never sees, stores, logs, or
forwards it. We only ever construct the command line. Unprivileged installs
(Go tools into your GOPATH) run without sudo at all.

Usage:
    bastion --install-tools            # interactive: shows plan, asks, installs
    bastion --install-tools --dry-run  # print the exact commands, install nothing
"""
from __future__ import annotations

import asyncio
import shutil
import sys

from .capabilities import detect

# tool -> how to get it. ("apt", pkg) needs sudo; ("go", module) does not.
INSTALL_PLAN = {
    "nuclei":       ("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "naabu":        ("go", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "subfinder":    ("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx":        ("go", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "dnsx":         ("go", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "katana":       ("go", "github.com/projectdiscovery/katana/cmd/katana@latest"),
    "gau":          ("go", "github.com/lc/gau/v2/cmd/gau@latest"),
    "ffuf":         ("go", "github.com/ffuf/ffuf/v2@latest"),
    "amass":        ("apt", "amass"),
    "masscan":      ("apt", "masscan"),
    "nmap":         ("apt", "nmap"),
    "sslscan":      ("apt", "sslscan"),
    "smbclient":    ("apt", "smbclient"),
    "netexec":      ("pipx", "netexec"),
    "enum4linux-ng":("pipx", "enum4linux-ng"),
    "bluetoothctl": ("apt", "bluez"),
    "hcitool":      ("apt", "bluez"),
    "bettercap":    ("apt", "bettercap"),
}


def _sudo_prefix() -> list[str]:
    # Let sudo prompt on its own TTY. No password ever passes through Bastion.
    return [] if shutil.which("sudo") is None else ["sudo"]


def plan_for(missing: list[str]) -> list[tuple[str, list[str]]]:
    """Return (tool, argv) for each installable missing tool."""
    steps: list[tuple[str, list[str]]] = []
    apt_pkgs: list[str] = []
    for tool in missing:
        spec = INSTALL_PLAN.get(tool)
        if not spec:
            continue
        method, ref = spec
        if method == "apt":
            apt_pkgs.append(ref)
        elif method == "go":
            steps.append((tool, ["go", "install", "-v", ref]))
        elif method == "pipx":
            steps.append((tool, ["pipx", "install", ref]))
    if apt_pkgs:
        pkgs = sorted(set(apt_pkgs))
        steps.insert(0, ("apt packages",
                         _sudo_prefix() + ["apt-get", "install", "-y", *pkgs]))
    return steps


def find_missing() -> list[str]:
    caps = detect()
    return [t for t in INSTALL_PLAN if not caps.has(t)
            and not (t in ("nxc",) and caps.has("netexec"))]


async def _run_visible(argv: list[str]) -> int:
    print(f"    $ {' '.join(argv)}")
    try:
        proc = await asyncio.create_subprocess_exec(*argv)
        await proc.wait()
        return proc.returncode or 0
    except FileNotFoundError:
        print(f"    ! {argv[0]} not found — install it first "
              f"({'Go toolchain' if argv[0]=='go' else argv[0]}).")
        return 1
    except OSError as exc:
        print(f"    ! {exc}")
        return 1


async def install_tools(*, dry_run: bool = False, assume_yes: bool = False,
                        only: list[str] | None = None) -> int:
    missing = find_missing()
    if only:
        missing = [t for t in missing if t in set(only)]
    if not missing:
        print("All known tools are already present.")
        return 0

    steps = plan_for(missing)
    print("\nMissing tools and how Bastion would install them:")
    print("  (apt steps use `sudo`, which will prompt YOU for the password — "
          "Bastion never sees it)\n")
    for tool, argv in steps:
        tag = "sudo " if argv and argv[0] == "sudo" else ""
        print(f"  • {tool:16} {tag}{' '.join(a for a in argv if a != 'sudo')}")
    print()

    if dry_run:
        print("Dry run — nothing installed.")
        return 0
    if not assume_yes:
        try:
            if input("Proceed with these installs? [y/N] ").strip().lower() \
                    not in ("y", "yes"):
                print("Aborted.")
                return 1
        except EOFError:
            return 1

    print()
    rc = 0
    for tool, argv in steps:
        print(f"  Installing {tool}...")
        code = await _run_visible(argv)
        rc |= code
        print(f"  {'done' if code == 0 else 'FAILED'}: {tool}\n")

    if any(a[1][0] == "go" for a in steps):
        print("Note: Go tools land in $(go env GOPATH)/bin — ensure it's on "
              "your PATH.")
    return rc
