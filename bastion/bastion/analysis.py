"""Unsupervised analysis over the asset graph.

This is where machine learning earns its place, and the scope is deliberately
narrow:

  1. CLUSTERING collapses an estate into a handful of readable groups. A survey
     that returns 4,000 hosts is unusable; the same survey expressed as twelve
     "estates" with a description each is something a human can act on. Grouping
     is by observable infrastructure shape — port profile, ASN, certificate
     issuer, header shape — so clusters mean something operational.

  2. ANOMALY DETECTION runs *within* each cluster, not across the whole estate.
     The interesting host is not the unusual one globally; it is the one that
     differs from its own peers. One box in a fleet of forty still on an old TLS
     stack is the finding. Globally it would be unremarkable.

  3. NAME-SHAPE STATISTICS flag machine-generated hostnames by character
     entropy, which separates auto-provisioned infrastructure from names a human
     chose. Not ML, just statistics, and it costs nothing.

Deliberately NOT here: supervised risk scoring. There are no labels for
"exploitable", so a classifier would encode the same heuristics as castle.py
while making them unexplainable. The rubric stays hand-written.

sklearn is optional. Without it, clustering degrades to exact-fingerprint
grouping and anomaly detection to robust z-scores, which recovers most of the
value at zero dependency cost — useful in a locked-down sandbox.
"""
from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .graph import AssetGraph
from .models import Asset

log = logging.getLogger("bastion.analysis")

try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:  # pragma: no cover
    HAVE_NUMPY = False

try:
    from sklearn.cluster import DBSCAN
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAVE_SKLEARN = True
except ImportError:  # pragma: no cover
    HAVE_SKLEARN = False


#: Ports used as binary features. Chosen for discriminative power, not frequency.
FEATURE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587,
                 636, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000,
                 8080, 8443, 9200, 27017]


@dataclass
class Estate:
    """A cluster of infrastructure that behaves like one thing."""
    cluster_id: int
    members: list[str] = field(default_factory=list)
    port_profile: list[int] = field(default_factory=list)
    orgs: list[str] = field(default_factory=list)
    outliers: list[tuple[str, float, str]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)

    def describe(self) -> str:
        ports = ", ".join(str(p) for p in self.port_profile[:6]) or "no open ports"
        org = self.orgs[0] if self.orgs else "unattributed"
        if self.cluster_id < 0:
            return f"{self.size} unclustered address(es) — no shared shape"
        return f"{self.size} address(es) on {org}, serving {ports}"


@dataclass
class AnalysisResult:
    estates: list[Estate] = field(default_factory=list)
    #: asset_key -> (score, human-readable reason)
    outliers: dict[str, tuple[float, str]] = field(default_factory=dict)
    generated_names: list[tuple[str, float]] = field(default_factory=list)
    method: str = "none"
    notes: list[str] = field(default_factory=list)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _features(graph: AssetGraph) -> tuple[list[str], list[list[float]], dict]:
    """Build one row per IP describing its observable infrastructure shape."""
    keys: list[str] = []
    rows: list[list[float]] = []
    meta: dict[str, dict] = {}

    org_vocab: dict[str, int] = {}
    issuer_vocab: dict[str, int] = {}

    for ip in graph.ips:
        services = graph.services_for(ip.key)
        ports = sorted({s.attrs.get("port") for s in services if s.attrs.get("port")})
        org = str(ip.attrs.get("org") or ip.attrs.get("isp") or "").lower()[:40]
        issuers = [str(s.attrs.get("cert_issuer") or "") for s in services]
        issuer = next((i for i in issuers if i), "")[:40]

        org_id = org_vocab.setdefault(org, len(org_vocab))
        issuer_id = issuer_vocab.setdefault(issuer, len(issuer_vocab))

        row = [1.0 if p in ports else 0.0 for p in FEATURE_PORTS]
        row += [
            float(len(ports)),
            float(org_id),
            float(issuer_id),
            float(len(ip.attrs.get("hostnames") or [])),
            float(sum(len(s.attrs.get("vulns") or []) for s in services)),
            1.0 if any("tlsv1.3" in str(s.attrs.get("tls_versions") or "").lower()
                       for s in services) else 0.0,
        ]
        keys.append(ip.key)
        rows.append(row)
        meta[ip.key] = {"ports": ports, "org": org or "unattributed",
                        "issuer": issuer, "service_count": len(services)}
    return keys, rows, meta


def analyse(graph: AssetGraph) -> AnalysisResult:
    result = AnalysisResult()
    keys, rows, meta = _features(graph)

    result.generated_names = _flag_generated_names(graph)

    if len(keys) < 3:
        result.method = "skipped"
        result.notes.append(
            f"Only {len(keys)} address(es) in the graph — clustering needs at "
            "least 3 to say anything meaningful.")
        return result

    if HAVE_SKLEARN and HAVE_NUMPY:
        labels = _cluster_sklearn(rows)
        result.method = "DBSCAN + IsolationForest"
    else:
        labels = _cluster_fingerprint(keys, meta)
        result.method = "exact fingerprint grouping (sklearn unavailable)"
        result.notes.append(
            "Install scikit-learn for density-based clustering and isolation "
            "forest scoring; falling back to exact port-profile grouping.")

    grouped: dict[int, list[str]] = defaultdict(list)
    for key, label in zip(keys, labels):
        grouped[int(label)].append(key)
        graph.assets[key].cluster = int(label)

    for cid, members in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        port_counter: Counter = Counter()
        orgs: Counter = Counter()
        for m in members:
            port_counter.update(meta[m]["ports"])
            orgs[meta[m]["org"]] += 1
        estate = Estate(
            cluster_id=cid,
            members=sorted(members),
            port_profile=[p for p, _ in port_counter.most_common(8)],
            orgs=[o for o, _ in orgs.most_common(3)],
        )
        idx = [keys.index(m) for m in members]
        scored = _score_outliers([rows[i] for i in idx], members)
        for key, score in scored:
            reason = _explain(key, meta, port_counter, len(members))
            estate.outliers.append((key, score, reason))
            result.outliers[key] = (score, reason)
            graph.assets[key].anomaly_score = score
        result.estates.append(estate)

    return result


def _cluster_sklearn(rows: list[list[float]]) -> list[int]:
    X = StandardScaler().fit_transform(np.asarray(rows, dtype=float))
    # eps tuned for scaled binary-heavy feature space; min_samples=2 so that a
    # pair of identical boxes still counts as a fleet.
    return DBSCAN(eps=2.2, min_samples=2).fit_predict(X).tolist()


def _cluster_fingerprint(keys: list[str], meta: dict) -> list[int]:
    seen: dict[tuple, int] = {}
    labels = []
    for k in keys:
        fp = (tuple(meta[k]["ports"]), meta[k]["org"])
        labels.append(seen.setdefault(fp, len(seen)))
    return labels


def _score_outliers(rows: list[list[float]], members: list[str],
                    top_fraction: float = 0.15) -> list[tuple[str, float]]:
    """Return the members that least resemble their own cluster."""
    if len(rows) < 4:
        return []

    if HAVE_SKLEARN and HAVE_NUMPY:
        X = np.asarray(rows, dtype=float)
        if X.std(axis=0).sum() == 0:
            return []                     # a perfectly uniform fleet
        contamination = min(0.25, max(0.05, top_fraction))
        forest = IsolationForest(contamination=contamination, random_state=0,
                                 n_estimators=200)
        raw = forest.fit(X).score_samples(X)      # lower = more anomalous
        threshold = float(np.quantile(raw, contamination))
        return [(members[i], round(float(-raw[i]), 3))
                for i in range(len(members)) if raw[i] <= threshold]

    if not HAVE_NUMPY:
        return []
    X = np.asarray(rows, dtype=float)
    median = np.median(X, axis=0)
    mad = np.median(np.abs(X - median), axis=0)
    mad[mad == 0] = 1.0
    z = np.abs((X - median) / mad).sum(axis=1)
    cutoff = np.quantile(z, 1 - top_fraction)
    return [(members[i], round(float(z[i]), 3))
            for i in range(len(members)) if z[i] >= cutoff and z[i] > 0]


def _explain(key: str, meta: dict, cluster_ports: Counter, n: int) -> str:
    """Say why a host stands out, in terms an analyst can verify."""
    mine = set(meta[key]["ports"])
    common = {p for p, c in cluster_ports.items() if c >= max(2, n * 0.6)}
    extra = sorted(mine - common)
    missing = sorted(common - mine)
    bits = []
    if extra:
        bits.append(f"open ports its peers do not have: {', '.join(map(str, extra))}")
    if missing:
        bits.append(f"missing ports its peers all have: {', '.join(map(str, missing))}")
    if meta[key]["issuer"]:
        bits.append(f"certificate issued by {meta[key]['issuer']}")
    return "; ".join(bits) if bits else "differs from peers across several features"


def _flag_generated_names(graph: AssetGraph, threshold: float = 3.6
                          ) -> list[tuple[str, float]]:
    """High character entropy in the leftmost label suggests a machine picked it.

    Auto-provisioned infrastructure, ephemeral cloud endpoints and some shadow
    IT show up this way. It is a lead, not a finding.
    """
    out = []
    for host in graph.hosts:
        label = host.key.split(".")[0]
        if len(label) < 8:
            continue
        e = shannon_entropy(label)
        if e >= threshold:
            out.append((host.key, round(e, 2)))
    return sorted(out, key=lambda x: -x[1])[:40]
