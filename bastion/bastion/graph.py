"""Fold raw observations into a deduplicated asset graph."""
from __future__ import annotations

from collections import defaultdict

from .models import Asset, AssetKind, Observation


class AssetGraph:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}

    def add(self, obs: Observation) -> None:
        asset = self.assets.get(obs.asset_key)
        if asset is None:
            asset = Asset(kind=obs.asset_kind, key=obs.asset_key)
            self.assets[obs.asset_key] = asset
        asset.merge(obs)

    def extend(self, observations: list[Observation]) -> None:
        for o in observations:
            self.add(o)

    # ---- views ----------------------------------------------------------
    def of_kind(self, kind: AssetKind) -> list[Asset]:
        return [a for a in self.assets.values() if a.kind is kind]

    @property
    def hosts(self) -> list[Asset]:
        return self.of_kind(AssetKind.HOST)

    @property
    def live_hosts(self) -> list[Asset]:
        return [h for h in self.hosts
                if h.attrs.get("resolves") and not h.attrs.get("wildcard_artifact")]

    @property
    def ips(self) -> list[Asset]:
        return self.of_kind(AssetKind.IP)

    @property
    def services(self) -> list[Asset]:
        return self.of_kind(AssetKind.SERVICE)

    def services_for(self, ip: str) -> list[Asset]:
        return [s for s in self.services if s.attrs.get("ip") == ip]

    def prune_wildcards(self) -> int:
        """Drop names that only exist because of a DNS wildcard."""
        doomed = [k for k, a in self.assets.items()
                  if a.kind is AssetKind.HOST and a.attrs.get("wildcard_artifact")]
        for k in doomed:
            del self.assets[k]
        return len(doomed)

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for a in self.assets.values():
            counts[a.kind.value] += 1
        counts["live_hosts"] = len(self.live_hosts)
        counts["corroborated"] = sum(1 for a in self.assets.values()
                                     if len(a.sources) > 1)
        return dict(counts)
