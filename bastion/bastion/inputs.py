"""Seed ingestion. An engagement starts from one or many seeds — a single
domain, a web-app URL, an IP, a CIDR, or a file/stream mixing all of these,
which is how a bug-bounty scope usually arrives.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .models import Target, parse_target


def _lines(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]          # drop comment for the whole line
        for chunk in line.replace(",", " ").split():
            entry = chunk.strip()
            if entry:
                out.append(entry)
    return out


def load_seeds(positional: list[str], list_file: str | None,
               ) -> tuple[list[Target], list[str]]:
    """Resolve CLI inputs into de-duplicated Targets.

    A positional argument is treated as a file if it names one on disk, else as
    a literal target. '-' anywhere means read newline/comma-separated seeds from
    stdin. Returns (targets, warnings-about-unparseable-entries).
    """
    raw: list[str] = []

    if list_file:
        if list_file == "-":
            raw += _lines(sys.stdin.read())
        else:
            raw += _lines(Path(list_file).read_text())

    for item in positional:
        if item == "-":
            raw += _lines(sys.stdin.read())
        elif Path(item).is_file():
            raw += _lines(Path(item).read_text())
        else:
            raw.append(item)

    targets: list[Target] = []
    seen: set[str] = set()
    warnings: list[str] = []
    for entry in raw:
        try:
            t = parse_target(entry)
        except ValueError:
            warnings.append(f"skipped unparseable seed: {entry!r}")
            continue
        sig = f"{t.kind.value}:{t.value}"
        if sig not in seen:
            seen.add(sig)
            targets.append(t)
    return targets, warnings


def engagement_name(targets: list[Target]) -> str:
    """A human label for a multi-seed engagement."""
    if not targets:
        return "engagement"
    if len(targets) == 1:
        return targets[0].value
    # Prefer the shortest registrable-looking domain as the engagement anchor.
    domains = [t.value for t in targets if t.kind.value == "domain"]
    anchor = min(domains, key=len) if domains else targets[0].value
    return f"{anchor} (+{len(targets) - 1} more)"
