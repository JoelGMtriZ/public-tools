"""Collector registry and the passive/active + black/grey boundaries.

Two orthogonal gates. Nothing sends packets at the target unless active mode is
on with a scope file that covers the target; nothing uses target credentials
unless they were supplied. Enforced at registration, selection, and execution.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Iterable, Type

from .capabilities import Capabilities
from .config import Config, ScopeError
from .models import Knowledge, Mode, Observation, Target, utcnow
from .net import HttpClient

log = logging.getLogger("bastion.registry")


@dataclass
class RunContext:
    target: Target
    cfg: Config
    http: HttpClient
    caps: Capabilities
    known_hosts: set[str] = field(default_factory=set)
    known_ips: set[str] = field(default_factory=set)
    # IPs derived from in-scope domain resolution are implicitly in scope.
    in_scope_ips: set[str] = field(default_factory=set)
    stop_event: object = None   # threading.Event — set to cancel the run

    @property
    def knowledge(self) -> Knowledge:
        return self.cfg.knowledge

    def assert_in_scope(self, host: str) -> None:
        if self.cfg.scope is None:
            raise ScopeError("active probe attempted with no scope file loaded")
        # IPs that resolved from an in-scope domain are implicitly in scope.
        if host in self.in_scope_ips:
            return
        self.cfg.scope.assert_host(host)

    def stopped(self) -> bool:
        return bool(self.stop_event and getattr(self.stop_event, 'is_set', lambda: False)())


class Collector:
    name: str = ""
    mode: Mode = Mode.PASSIVE
    requires_creds: bool = False     # True => grey-box only
    requires_tool: str | None = None  # external binary this collector shells to
    requires_rf: bool = False         # proximity/RF; gated on cfg.rf_authorized
    stage: int = 0
    provides: str = ""

    def applicable(self, ctx: RunContext) -> bool:
        return True

    async def run(self, ctx: RunContext) -> list[Observation]:
        raise NotImplementedError

    def evidence(self, detail: str = "", url: str | None = None,
                 data_timestamp=None):
        from .models import Evidence
        prefix = "active:" if self.mode is Mode.ACTIVE else ""
        return Evidence(source=f"{prefix}{self.name}", observed_at=utcnow(),
                        detail=detail, url=url, data_timestamp=data_timestamp)


_REGISTRY: dict[str, Type[Collector]] = {}


def register(cls: Type[Collector]) -> Type[Collector]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must declare a name")
    if not isinstance(cls.mode, Mode):
        raise ValueError(f"{cls.name} must declare mode as a Mode enum")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate collector name {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def all_collectors() -> list[Type[Collector]]:
    return sorted(_REGISTRY.values(), key=lambda c: (c.stage, c.name))


def select(cfg: Config, ctx: RunContext, *, want_active: bool,
           only: Iterable[str] | None = None) -> tuple[list[Collector], list[str]]:
    """Return (collectors_to_run, notes_about_what_was_skipped)."""
    only = set(only) if only else None
    chosen: list[Collector] = []
    notes: list[str] = []

    active_ok = bool(want_active and cfg.allow_active and cfg.scope)
    if want_active and not active_ok:
        raise ScopeError(
            "Active mode requires --scope pointing at a file of authorised "
            "domains/CIDRs. Refusing to run active collectors.")
    if active_ok and not cfg.scope.permits_target(ctx.target):
        raise ScopeError(
            f"target {ctx.target.value} is not covered by {cfg.scope.source_path}")

    grey = cfg.knowledge is Knowledge.GREY

    # Passive collectors that reach out to the internet. In --offline mode
    # (internal / air-gapped engagements) we run only what talks to the target
    # or the local resolver.
    INTERNET_SOURCES = {"crtsh", "shodan", "censys", "securitytrails",
                        "virustotal", "urlscan", "recordedfuture", "wayback"}

    for cls in all_collectors():
        if only and cls.name not in only:
            continue
        # Proximity/RF collectors have their own authorisation, independent of
        # the network scope — admit them iff RF was explicitly acknowledged.
        if getattr(cls, "requires_rf", False):
            if not cfg.rf_authorized:
                continue
            inst = cls()
            if cls.requires_tool and not ctx.caps.has(cls.requires_tool):
                continue
            if inst.applicable(ctx):
                chosen.append(inst)
            continue
        if cfg.offline and cls.mode is Mode.PASSIVE and cls.name in INTERNET_SOURCES:
            notes.append(f"{cls.name}: skipped (--offline)")
            continue
        if cls.mode is Mode.ACTIVE and not active_ok:
            continue
        if cls.requires_creds and not grey:
            continue
        inst = cls()
        if cls.requires_tool and not ctx.caps.has(cls.requires_tool):
            if cls.mode is Mode.ACTIVE and active_ok:
                notes.append(f"{cls.name}: needs `{cls.requires_tool}` "
                             "(not found) — skipped")
            continue
        if not inst.applicable(ctx):
            continue
        chosen.append(inst)
    return chosen, notes


async def execute(collectors: list[Collector], ctx: RunContext,
                  on_progress: Callable[[str, int, str], None] | None = None
                  ) -> list[Observation]:
    observations: list[Observation] = []
    by_stage: dict[int, list[Collector]] = {}
    for c in collectors:
        by_stage.setdefault(c.stage, []).append(c)

    for stage in sorted(by_stage):
        if ctx.stopped():
            log.info("Stop event set — halting at stage %d", stage)
            break
        batch = by_stage[stage]
        for c in batch:
            if on_progress:
                on_progress(c.name, 0, f"starting {c.provides or c.name}")
        results = await asyncio.gather(*(_guard(c, ctx) for c in batch))
        for collector, obs in zip(batch, results):
            observations.extend(obs)
            # Derive scope: any IP associated with an in-scope domain is in scope.
            for o in obs:
                if o.asset_kind.value == "host":
                    ctx.known_hosts.add(o.asset_key)
                elif o.asset_kind.value == "ip":
                    ctx.known_ips.add(o.asset_key)
                    # Mark the IP in-scope if any related name is in scope.
                    for related in o.related or []:
                        if ctx.cfg.scope and ctx.cfg.scope.permits_host(related):
                            ctx.in_scope_ips.add(o.asset_key)
                            break
                    else:
                        # Also in-scope if the seed target itself resolved to it.
                        if ctx.cfg.scope and ctx.cfg.scope.permits_host(ctx.target.value):
                            ctx.in_scope_ips.add(o.asset_key)
            detail = _obs_summary(obs)
            if on_progress:
                on_progress(collector.name, len(obs), detail)
    return observations


def _obs_summary(obs: list) -> str:
    if not obs:
        return "nothing found"
    kinds: dict[str, int] = {}
    for o in obs:
        kinds[o.asset_kind.value] = kinds.get(o.asset_kind.value, 0) + 1
    parts = [f"{n} {k}{'s' if n!=1 else ''}" for k, n in sorted(kinds.items())]
    return ", ".join(parts)


async def _guard(collector: Collector, ctx: RunContext) -> list[Observation]:
    try:
        return await collector.run(ctx)
    except ScopeError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("collector %s failed: %s", collector.name, exc)
        return []
