"""End-to-end exercise on a synthetic estate — no network required.

Builds Observations by hand to cover every lead path (edge/origin split, auth
surfaces, exposed services incl. active-observed, obsolete TLS, subdomain
takeover, version disclosure, nuclei-confirmed, external intel), folds them
through the real graph/analysis/attackmap, simulates an LLM synthesis payload,
and renders terminal + NDJSON + JSON + HTML.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bastion.analysis import analyse
from bastion.castle import build_attackmap
from bastion.graph import AssetGraph
from bastion.models import (AssetKind, Evidence, Observation, service_key, utcnow)
from bastion.report import render_html, render_json, render_ndjson, render_terminal
from bastion.synth import apply_synthesis


def ev(src, detail="", active=False):
    return Evidence(source=("active:" if active else "") + src,
                    observed_at=utcnow(), detail=detail)


def estate() -> AssetGraph:
    g = AssetGraph()
    O = Observation

    # Edge-fronted production
    g.add(O(AssetKind.HOST, "www.acme-example.com",
            attrs={"resolves": True, "ips": ["104.16.10.10"]},
            related=["104.16.10.10"], evidence=ev("crtsh")))
    g.add(O(AssetKind.IP, "104.16.10.10",
            attrs={"org": "Cloudflare, Inc.", "isp": "Cloudflare"},
            evidence=ev("shodan")))
    g.add(O(AssetKind.SERVICE, service_key("104.16.10.10", 443),
            attrs={"ip": "104.16.10.10", "port": 443, "product": "cloudflare"},
            related=["104.16.10.10"], evidence=ev("shodan")))

    # Naked origin beside the CDN (the prize)
    g.add(O(AssetKind.IP, "198.51.100.7",
            attrs={"org": "ACME Hosting", "isp": "ACME"}, evidence=ev("censys")))
    for port, prod, ver in [(443, "nginx", "1.18.0"), (22, "OpenSSH", "7.4"),
                            (3306, "MySQL", "5.7.31"), (6379, "Redis", "5.0.7"),
                            (9200, "Elasticsearch", "6.8.0"),
                            (8080, "Jetty", "9.4.30")]:
        g.add(O(AssetKind.SERVICE, service_key("198.51.100.7", port),
                attrs={"ip": "198.51.100.7", "port": port, "product": prod,
                       "version": ver},
                related=["198.51.100.7"], evidence=ev("shodan")))
    # active-observed obsolete TLS on the origin
    g.add(O(AssetKind.SERVICE, service_key("198.51.100.7", 443),
            attrs={"ip": "198.51.100.7", "port": 443,
                   "tls_versions": ["TLSv1.0", "TLSv1.2"],
                   "tls_obsolete": ["TLSv1.0"]},
            related=["198.51.100.7"], evidence=ev("tlsprobe", active=True)))

    # Auth surface
    g.add(O(AssetKind.HOST, "vpn.acme-example.com",
            attrs={"resolves": True, "ips": ["198.51.100.9"]},
            related=["198.51.100.9"], evidence=ev("crtsh")))
    g.add(O(AssetKind.IP, "198.51.100.9", attrs={"org": "ACME Hosting"},
            evidence=ev("dns")))

    # Postern: live staging
    g.add(O(AssetKind.HOST, "dev-admin.acme-example.com",
            attrs={"resolves": True, "ips": ["198.51.100.7"]},
            related=["198.51.100.7"], evidence=ev("crtsh")))

    # Subdomain takeover: dangling CNAME
    g.add(O(AssetKind.HOST, "legacy.acme-example.com",
            attrs={"resolves": False, "cname": "acme-old.s3.amazonaws.com"},
            evidence=ev("crtsh")))

    # nuclei-confirmed exposure (active)
    g.add(O(AssetKind.ENDPOINT, "http://dev-admin.acme-example.com/.git/config",
            attrs={"nuclei_template": "git-config", "nuclei_name": "Exposed .git/config",
                   "nuclei_severity": "medium", "nuclei_tags": ["exposure", "config"],
                   "nuclei_cves": [], "matched_at": "http://dev-admin.acme-example.com/.git/config"},
            evidence=ev("nuclei", active=True)))
    g.add(O(AssetKind.ENDPOINT, "https://www.acme-example.com/redirect",
            attrs={"nuclei_template": "open-redirect", "nuclei_name": "Open Redirect",
                   "nuclei_severity": "low", "nuclei_tags": ["redirect"],
                   "matched_at": "https://www.acme-example.com/redirect?url="},
            evidence=ev("nuclei", active=True)))

    # External intel
    g.add(O(AssetKind.IP, "198.51.100.7",
            attrs={"rf_score": 72, "rf_rules": ["Recent Botnet C2", "Historical Malware"]},
            evidence=ev("recordedfuture")))
    return g


def fake_llm_synth(amap):
    """Simulate what a local model would return, grounded in real lead ids."""
    leads = amap.leads
    redis = next((l for l in leads if "Redis" in l.title), None)
    gitcfg = next((l for l in leads if "git" in l.title.lower()), None)
    naked = next((l for l in leads if "Origin reachable" in l.title), None)
    chains = []
    if naked and redis:
        chains.append({
            "hypothesis": "Reach the origin, then take the unauth Redis to RCE",
            "steps": [naked.fingerprint, redis.fingerprint],
            "rationale": "Origin is reachable beside the CDN, and 6379 answers "
                         "there — module-load or cron-write gets code exec."})
    avenues = []
    if gitcfg:
        avenues.append({
            "name": "Source disclosure via exposed .git",
            "objective": "Creds",
            "steps": [gitcfg.fingerprint] + ([redis.fingerprint] if redis else []),
            "narrative": "dev-admin leaks .git/config — pull the repo, mine "
                         "history for secrets, then pivot to the origin's Redis."})
    return {"summary": "Skip the CDN: origin 198.51.100.7 is directly reachable "
            "and runs unauthenticated Redis (6379) beside a legacy-TLS listener. "
            "Fastest path to RCE. In parallel, dev-admin's exposed .git likely "
            "yields source and secrets; legacy.acme-example.com is a clean S3 "
            "subdomain takeover.",
            "avenues": avenues, "chains": chains, "model": "qwen2.5:32b (simulated)"}


def main():
    g = estate()
    g.prune_wildcards()
    analyse(g)
    amap = build_attackmap(g, "acme-example.com", "grey")

    synth = fake_llm_synth(amap)
    apply_synthesis(amap, synth)

    print(render_terminal(amap, synth=synth, color=True, top=14))

    out = Path(__file__).resolve().parent.parent / "sample_report.html"
    out.write_text(render_html(amap, mode="active", synth=synth,
                               sources=["crtsh", "shodan", "censys", "dns",
                                        "active:tlsprobe", "active:nuclei",
                                        "recordedfuture"], elapsed=42.7))
    (out.parent / "sample.ndjson").write_text(render_ndjson(amap))
    (out.parent / "sample.json").write_text(
        render_json(amap, mode="active", sources=["crtsh", "shodan"], synth=synth))
    print(f"\nHTML  -> {out}")
    print(f"NDJSON-> {out.parent/'sample.ndjson'}  ({len(amap.leads)} leads)")
    print(f"leads={len(amap.leads)} avenues={len(amap.avenues)} "
          f"confirmed={amap.confirmed}")


if __name__ == "__main__":
    main()
