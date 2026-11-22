"""The run pipeline: collect -> graph -> prune -> analyse -> map -> synth.

Multiple seeds fold into ONE engagement graph, so shared infrastructure across a
bug-bounty scope (an IP that backs three of the in-scope domains, a cert that
ties two brands together) is correlated rather than split across reports.
"""
from __future__ import annotations

import time

from . import active, discovery, rf, smb, sources  # noqa: F401  (register collectors)
from .analysis import analyse
from .capabilities import detect
from .castle import AttackMap, build_attackmap
from .config import Config
from .graph import AssetGraph
from .inputs import engagement_name
from .models import Target, TargetKind
from .net import HttpClient
from .registry import RunContext, execute, select
from .store import Store
from .synth import apply_synthesis, synthesise


async def run(targets, cfg: Config, *, want_active: bool,
              on_progress=None, stop_event=None) -> tuple[AttackMap, dict, list[str], float, dict | None]:
    if isinstance(targets, Target):
        targets = [targets]
    t0 = time.monotonic()
    caps = detect()
    store = Store(cfg.cache_path)
    graph = AssetGraph()
    all_notes: list[str] = []
    synth = None

    async with HttpClient(cfg, store) as http:
        for seed in targets:
            ctx = RunContext(target=seed, cfg=cfg, http=http, caps=caps,
                        stop_event=stop_event)
            if seed.kind is TargetKind.DOMAIN:
                ctx.known_hosts.add(seed.value)
            elif seed.kind is TargetKind.IP:
                ctx.known_ips.add(seed.value)

            collectors, notes = select(cfg, ctx, want_active=want_active)
            all_notes += [f"[{seed.value}] {n}" for n in notes]
            observations = await execute(collectors, ctx, on_progress=on_progress)
            for obs in observations:
                graph.add(obs)

        graph.prune_wildcards()
        analyse(graph)

        name = engagement_name(list(targets))
        amap = build_attackmap(graph, name, cfg.knowledge.value)

        if cfg.llm.enabled:
            synth = await synthesise(amap, cfg.llm, http)
            if synth:
                apply_synthesis(amap, synth)

    sources_used = sorted({e.source for a in graph.assets.values()
                           for e in a.evidence})
    elapsed = time.monotonic() - t0
    return amap, {"notes": all_notes, "caps": caps}, sources_used, elapsed, synth
