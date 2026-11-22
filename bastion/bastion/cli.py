"""Bastion command line — terminal-first, pipe-friendly.

    bastion example.com                         # single seed
    bastion a.com b.com 10.0.0.0/24             # several seeds, one engagement
    bastion -l scope.txt                        # a list file (domains/URLs/CIDRs)
    cat scope.txt | bastion -                   # seeds from stdin
    bastion example.com --ndjson | jq .
    bastion -l scope.txt --active --scope scope.txt
    bastion -l scope.txt --active --scope scope.txt --nuclei
    bastion example.com --active --scope s.txt --bearer $TOKEN   # grey-box
    bastion -l internal.txt --active --scope s.txt --offline     # internal net
    bastion example.com --llm --brief           # local model synthesis
    bastion example.com --llm --llm-setup       # bootstrap a local model first
    bastion --egress                            # print the firewall allowlist
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .config import Config, LLMConfig, Scope, ScopeError
from .config import TargetCreds
from .inputs import load_seeds
from .pipeline import run
from .report import render_html, render_json, render_ndjson, render_terminal


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bastion",
        description="Offensive recon mapper — the scout that maps the castle.")
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="domain, URL, IP, CIDR, a file of these, or '-' for stdin")
    p.add_argument("-l", "--list", metavar="FILE",
                   help="file of seeds (one per line; '-' for stdin)")

    g = p.add_argument_group("reconnaissance")
    g.add_argument("--active", action="store_true",
                   help="enable active collectors (requires --scope)")
    g.add_argument("--scope", metavar="FILE",
                   help="authorised-scope file for active probing")
    g.add_argument("--nuclei", action="store_true",
                   help="run nuclei templated checks (implies --active)")
    g.add_argument("--offline", action="store_true",
                   help="disable all internet recon sources (internal/air-gapped)")
    g.add_argument("--mode", choices=["stealth", "balanced", "aggressive"],
                   default="balanced", help="scan timing/breadth profile")
    g.add_argument("--rf-authorized", action="store_true",
                   help="enable Bluetooth/BLE/AirDrop proximity recon — you "
                        "confirm physical authorisation (passive presence only)")

    gb = p.add_argument_group("grey-box (target credentials)")
    gb.add_argument("--cookie", help="Cookie header value to send to the target")
    gb.add_argument("--bearer", help="Bearer token for the target")
    gb.add_argument("--auth", metavar="USER:PASS", help="HTTP basic auth")
    gb.add_argument("--header", action="append", default=[], metavar="K:V",
                    help="extra header for the target (repeatable)")

    ll = p.add_argument_group("attack-path synthesis (local LLM)")
    ll.add_argument("--llm", action="store_true", help="enable LLM synthesis")
    ll.add_argument("--brief", action="store_true", help="alias for --llm")
    ll.add_argument("--llm-url", default=None, help="override BASTION_LLM_URL")
    ll.add_argument("--llm-model", default=None, help="override BASTION_LLM_MODEL")
    ll.add_argument("--llm-setup", action="store_true",
                    help="bootstrap a local model (install Ollama + pull), with consent")
    ll.add_argument("--llm-tier", choices=["min", "small", "balanced", "moe"],
                    default=None, help="model size tier for --llm-setup")
    ll.add_argument("--llm-tiers", action="store_true",
                    help="list the local model tiers and exit")
    ll.add_argument("--yes", action="store_true",
                    help="assume yes for --llm-setup prompts")

    out = p.add_argument_group("output")
    out.add_argument("--ndjson", action="store_true",
                     help="one JSON lead per line (implies quiet)")
    out.add_argument("--json", metavar="FILE", nargs="?", const="-",
                     help="full JSON (FILE or stdout)")
    out.add_argument("--html", metavar="FILE", help="shareable HTML report")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--top", type=int, default=25, help="leads shown in terminal")
    out.add_argument("--egress", action="store_true",
                     help="print the outbound firewall allowlist and exit")

    p.add_argument("--cache", default="./bastion.sqlite")
    p.add_argument("-v", "--verbose", action="count", default=0)

    util = p.add_argument_group("setup & interfaces")
    util.add_argument("--install-tools", action="store_true",
                      help="install missing scanners (sudo prompts you directly)")
    util.add_argument("--dry-run", action="store_true",
                      help="with --install-tools: print commands, install nothing")
    util.add_argument("--configure-keys", action="store_true",
                      help="interactively set recon-source API keys")
    util.add_argument("--export-keys", action="store_true",
                      help="write keys into subfinder's provider-config format")
    util.add_argument("--keys", metavar="FILE", default=None,
                      help="path to the keys.env file")
    util.add_argument("--web", action="store_true",
                      help="launch the localhost control panel")
    util.add_argument("--web-port", type=int, default=8899)
    util.add_argument("--web-host", default="127.0.0.1",
                      help="interface to bind the web UI (use 0.0.0.0 inside Docker)")
    return p


def _target_creds(args) -> TargetCreds:
    basic = None
    if args.auth and ":" in args.auth:
        u, _, pw = args.auth.partition(":")
        basic = (u, pw)
    headers = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    return TargetCreds(cookie=args.cookie, bearer=args.bearer, basic=basic,
                       headers=headers)


def _build_cfg(args) -> Config:
    from .config import SCAN_PROFILES
    from pathlib import Path as _P
    cfg = Config(cache_path=Path(args.cache))
    if args.keys:
        cfg.keys_path = _P(args.keys).expanduser()
    # Load keys.env into the environment (real env vars still win).
    from . import keys as _keys
    _keys.merge_into_environ(cfg.keys_path)
    cfg.creds = __import__("bastion.config", fromlist=["Credentials"]).Credentials.from_env()
    cfg.offline = args.offline
    cfg.profile = SCAN_PROFILES[args.mode]
    cfg.rf_authorized = args.rf_authorized
    cfg.target_creds = _target_creds(args)
    if args.llm or args.brief or args.llm_setup:
        cfg.llm = LLMConfig.from_env()
        cfg.llm.enabled = args.llm or args.brief
        if args.llm_tier:
            cfg.llm.tier = args.llm_tier
        if args.llm_url:
            cfg.llm.base_url = args.llm_url
        if args.llm_model:
            cfg.llm.model = args.llm_model
    return cfg


async def _amain(args) -> int:
    quiet = args.ndjson
    logging.basicConfig(
        level=logging.ERROR if quiet else
        [logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

    # informational modes that don't need targets
    if args.llm_tiers:
        from .llmsetup import print_tiers
        print_tiers()
        return 0
    if args.egress:
        from . import egress
        cfg = _build_cfg(args)
        out = egress.render_json(cfg) if args.json is not None \
            else egress.render_text(cfg)
        print(out)
        return 0
    if args.install_tools:
        from .install import install_tools
        return await install_tools(dry_run=args.dry_run, assume_yes=args.yes)
    if args.configure_keys:
        from .keys import configure_interactive
        cfg = _build_cfg(args)
        configure_interactive(cfg.keys_path)
        return 0
    if args.export_keys:
        from .keys import export_subfinder
        cfg = _build_cfg(args)
        dest = export_subfinder(cfg.keys_path, cfg.creds)
        print(f"  → subfinder provider-config written to {dest}")
        return 0
    if args.web:
        from .webui import serve
        cfg = _build_cfg(args)
        serve(cfg, host=args.web_host, port=args.web_port)
        return 0

    cfg = _build_cfg(args)

    # optional LLM bootstrap before the run
    if args.llm_setup:
        from .llmsetup import ensure_ollama
        model = await ensure_ollama(cfg.llm.base_url, tier=cfg.llm.tier,
                                    assume_yes=args.yes)
        if model:
            cfg.llm.model = model
            cfg.llm.enabled = True
        elif not (args.llm or args.brief):
            return 0

    seeds, warnings = load_seeds(args.targets, args.list)
    for w in warnings:
        print(f"  ! {w}", file=sys.stderr)
    if not seeds:
        print("bastion: no valid targets. Give a domain/URL/IP/CIDR, a file, "
              "or '-l FILE'.", file=sys.stderr)
        return 2

    want_active = args.active or args.nuclei
    cfg.allow_active = want_active
    cfg.run_nuclei = args.nuclei

    if want_active:
        if not args.scope:
            print("bastion: --active/--nuclei require --scope FILE "
                  "(authorised targets). Refusing to probe.", file=sys.stderr)
            return 2
        try:
            cfg.scope = Scope.load(args.scope)
        except ScopeError as exc:
            print(f"bastion: {exc}", file=sys.stderr)
            return 2

    def progress(name: str, n: int) -> None:
        if not quiet:
            print(f"  · {name}: {n}", file=sys.stderr)

    try:
        amap, meta, sources_used, elapsed, synth = await run(
            seeds, cfg, want_active=want_active,
            on_progress=None if quiet else progress)
    except ScopeError as exc:
        print(f"bastion: {exc}", file=sys.stderr)
        return 2
    except asyncio.CancelledError:
        print("\n  Scan interrupted — no results to show.", file=sys.stderr)
        return 130

    for note in meta.get("notes", []):
        print(f"  ! {note}", file=sys.stderr)

    mode = "active" if want_active else "passive"
    if cfg.offline:
        mode += "/offline"

    if args.ndjson:
        sys.stdout.write(render_ndjson(amap) + "\n")
        return 0

    if args.json is not None:
        blob = render_json(amap, mode=mode, sources=sources_used, synth=synth)
        if args.json == "-":
            sys.stdout.write(blob + "\n")
        else:
            Path(args.json).write_text(blob)
            print(f"  → JSON written to {args.json}", file=sys.stderr)

    if args.html:
        Path(args.html).write_text(render_html(
            amap, mode=mode, sources=sources_used, synth=synth, elapsed=elapsed))
        print(f"  → HTML written to {args.html}", file=sys.stderr)

    if args.json is None or args.json != "-":
        color = False if args.no_color else None
        sys.stdout.write(render_terminal(amap, synth=synth, color=color,
                                         top=args.top) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("\n\n  Scan stopped by user (Ctrl+C).", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
