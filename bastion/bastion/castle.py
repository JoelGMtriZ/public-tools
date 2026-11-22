"""Read the asset graph for the attacker: leads, then avenues of approach.

No posture score. The scout marks where the walls are weak and hands the
general ranked routes in. Leads are attackable observations rated by what they
yield (Impact) and how confirmed they are (Exploitability); Avenues group leads
into routes toward an objective. The rubric is hand-written and transparent —
no learned scorer, because there is no ground truth for "exploitable".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .graph import AssetGraph
from .models import (AssetKind, Avenue, Confidence, Exploitability, Impact,
                     Lead, PLAN_ZONES, Zone, ZONE_INTENT, ZONE_LABEL)

# --- signature tables -------------------------------------------------------

EDGE_PROVIDERS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly",
    "cloudfront": "AWS CloudFront", "incapsula": "Imperva", "imperva": "Imperva",
    "sucuri": "Sucuri", "azure front door": "Azure Front Door",
    "stackpath": "StackPath", "edgecast": "Edgecast", "distil": "Imperva",
}

GATEHOUSE_NAMES = ["vpn", "sso", "auth", "login", "signin", "remote", "citrix",
                   "owa", "webmail", "mail", "portal", "adfs", "okta", "duo",
                   "rdgateway", "rdweb", "gateway", "connect", "access", "idp",
                   "saml", "oauth", "keycloak"]

POSTERN_NAMES = ["dev", "development", "staging", "stage", "test", "testing",
                 "uat", "qa", "sandbox", "old", "legacy", "deprecated",
                 "backup", "bak", "tmp", "temp", "demo", "beta", "alpha",
                 "preview", "internal", "intranet", "jenkins", "gitlab", "git",
                 "jira", "confluence", "phpmyadmin", "pma", "adminer", "admin",
                 "cpanel", "webdisk", "grafana", "kibana", "nagios", "zabbix",
                 "vault", "consul", "rancher", "harbor", "nexus", "sonar"]

# port -> (label, Impact, Exploitability, Zone, move)
SERVICE_LEADS: dict[int, tuple] = {
    23:   ("Telnet exposed", Impact.CREDENTIALS, Exploitability.LIKELY, Zone.GATEHOUSE,
           "Cleartext auth — sniff or brute; often default creds on appliances."),
    445:  ("SMB exposed", Impact.RCE, Exploitability.POSSIBLE, Zone.GARRISON,
           "Enumerate shares/null sessions; check for known SMB RCE by version."),
    3389: ("RDP exposed", Impact.FOOTHOLD, Exploitability.POSSIBLE, Zone.GATEHOUSE,
           "Spray credentials, check NLA; BlueKeep-class by build."),
    5900: ("VNC exposed", Impact.FOOTHOLD, Exploitability.POSSIBLE, Zone.GATEHOUSE,
           "Test for no-auth VNC; then credential spray."),
    3306: ("MySQL exposed", Impact.DATA, Exploitability.LIKELY, Zone.GARRISON,
           "Try default/empty root; enumerate if reachable — likely misconfig."),
    5432: ("PostgreSQL exposed", Impact.DATA, Exploitability.LIKELY, Zone.GARRISON,
           "Test default creds and trust auth; enumerate databases."),
    6379: ("Redis exposed", Impact.RCE, Exploitability.LIKELY, Zone.GARRISON,
           "Unauth Redis is often RCE via module load or cron write. High value."),
    9200: ("Elasticsearch exposed", Impact.DATA, Exploitability.LIKELY, Zone.GARRISON,
           "Unauth ES usually dumps every index. Check _cat/indices."),
    11211:("Memcached exposed", Impact.DATA, Exploitability.LIKELY, Zone.GARRISON,
           "Unauth; dump items, and it is a UDP amplification vector."),
    27017:("MongoDB exposed", Impact.DATA, Exploitability.LIKELY, Zone.GARRISON,
           "Historically unauth by default; enumerate databases."),
    2375: ("Docker API exposed", Impact.RCE, Exploitability.LIKELY, Zone.GARRISON,
           "Unauth Docker socket = host RCE via privileged container."),
    2379: ("etcd exposed", Impact.CREDENTIALS, Exploitability.LIKELY, Zone.GARRISON,
           "Cluster secrets frequently readable — pull keys."),
    6443: ("Kubernetes API exposed", Impact.RCE, Exploitability.POSSIBLE, Zone.GARRISON,
           "Test anonymous-auth; if bound, cluster takeover."),
    22:   ("SSH exposed", Impact.FOOTHOLD, Exploitability.POSSIBLE, Zone.GATEHOUSE,
           "Note version for known bugs; key/credential spray if in scope."),
    21:   ("FTP exposed", Impact.DATA, Exploitability.POSSIBLE, Zone.GARRISON,
           "Test anonymous login; capture banner for version bugs."),
    161:  ("SNMP exposed", Impact.RECON, Exploitability.POSSIBLE, Zone.GARRISON,
           "Try public/private community strings; walk for config + creds."),
    1433: ("MSSQL exposed", Impact.DATA, Exploitability.POSSIBLE, Zone.GARRISON,
           "Default sa creds; xp_cmdshell if you land."),
    10000:("Webmin exposed", Impact.RCE, Exploitability.POSSIBLE, Zone.POSTERN,
           "Version-dependent RCE history; fingerprint the build."),
    9090: ("Admin/metrics port", Impact.RECON, Exploitability.POSSIBLE, Zone.POSTERN,
           "Often Prometheus/OpenShift console — enumerate."),
}

OBSOLETE_TLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
WEAK_CIPHER_TOKENS = ["null", "export", "anon", "rc4", "des-cbc3", "3des",
                      "md5", "des"]

TAKEOVER_TARGETS = ["s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
                    "trafficmanager.net", "blob.core.windows.net",
                    "herokuapp.com", "github.io", "ghost.io", "wpengine.com",
                    "pantheonsite.io", "fastly.net", "netlify.app", "surge.sh",
                    "readthedocs.io", "zendesk.com", "statuspage.io",
                    "unbouncepages.com", "azureedge.net", "cloudapp.net"]

NUCLEI_IMPACT = {  # nuclei severity -> (Impact hint, Exploitability)
    "critical": (Impact.RCE, Exploitability.CONFIRMED),
    "high":     (Impact.FOOTHOLD, Exploitability.CONFIRMED),
    "medium":   (Impact.DATA, Exploitability.CONFIRMED),
    "low":      (Impact.RECON, Exploitability.CONFIRMED),
    "info":     (Impact.RECON, Exploitability.CONFIRMED),
}


@dataclass
class ZoneView:
    zone: Zone
    leads: list[Lead] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # defences we noticed (as obstacles)

    @property
    def label(self) -> str:
        return ZONE_LABEL[self.zone]

    @property
    def intent(self) -> str:
        return ZONE_INTENT[self.zone]

    @property
    def top_priority(self) -> float:
        return max((l.priority for l in self.leads), default=0.0)


@dataclass
class AttackMap:
    target: str
    knowledge: str
    zones: dict[Zone, ZoneView]
    avenues: list[Avenue]
    graph: AssetGraph

    @property
    def leads(self) -> list[Lead]:
        out = [l for z in self.zones.values() for l in z.leads]
        return sorted(out, key=lambda l: (-l.priority, l.zone.value))

    def leads_by_impact(self) -> dict[str, int]:
        c = {i.label: 0 for i in reversed(list(Impact))}
        for l in self.leads:
            c[l.impact.label] += 1
        return c

    @property
    def confirmed(self) -> int:
        return sum(1 for l in self.leads
                   if l.exploitability is Exploitability.CONFIRMED)

    @property
    def headline(self) -> str:
        n = len(self.leads)
        top = self.leads[0] if self.leads else None
        if not top:
            return "No attackable leads surfaced."
        return (f"{n} leads across {sum(1 for z in self.zones.values() if z.leads)} "
                f"zones; {self.confirmed} confirmed. "
                f"Best: {top.title} ({top.tag}).")


def _matches(name: str, fragments: list[str]) -> str | None:
    labels = re.split(r"[.\-_]", name.lower())
    for f in fragments:
        if f in labels:
            return f
    return None


def _edge(text: str) -> str | None:
    low = (text or "").lower()
    for token, label in EDGE_PROVIDERS.items():
        if token in low:
            return label
    return None


def build_attackmap(graph: AssetGraph, target: str, knowledge: str) -> AttackMap:
    zones = {z: ZoneView(z) for z in Zone}

    def add(zone: Zone, lead: Lead) -> None:
        zones[zone].leads.append(lead)

    edge_ips: set[str] = set()
    providers: dict[str, int] = {}
    for ip in graph.ips:
        blob = " ".join(str(ip.attrs.get(k) or "")
                        for k in ("org", "isp", "hostnames"))
        prov = _edge(blob)
        if prov:
            providers[prov] = providers.get(prov, 0) + 1
            edge_ips.add(ip.key)
    for prov, n in providers.items():
        zones[Zone.CURTAIN_WALL].notes.append(f"{prov} fronts {n} address(es)")

    # Curtain wall: origin reachable beside the edge is the prize here.
    web_ips = {s.attrs["ip"] for s in graph.services
               if s.attrs.get("port") in (80, 443) and s.attrs.get("ip")}
    naked = web_ips - edge_ips
    if naked and providers:
        add(Zone.CURTAIN_WALL, Lead(
            Zone.CURTAIN_WALL, "Origin reachable beside the CDN", ", ".join(sorted(naked)[:4]),
            Impact.FOOTHOLD, Exploitability.LIKELY,
            move="Hit these IPs directly with a Host header for the app — you "
                 "bypass the WAF/CDN entirely.",
            detail=f"{len(naked)} web address(es) sit outside the "
                   f"{'/'.join(providers)} edge.",
            source_tool="castle"))

    # Gatehouse from names
    for host in graph.live_hosts:
        frag = _matches(host.key, GATEHOUSE_NAMES)
        if frag:
            add(Zone.GATEHOUSE, Lead(
                Zone.GATEHOUSE, f"Auth surface exposed ({frag})", host.key,
                Impact.CREDENTIALS, Exploitability.POSSIBLE,
                move="Fingerprint the login; check MFA, lockout, default creds, "
                     "and known bypasses for the product.",
                confidence=host.confidence, evidence=host.evidence[:2],
                source_tool="castle"))

    # Services
    for svc in graph.services:
        port = svc.attrs.get("port")
        spec = SERVICE_LEADS.get(port)
        if spec:
            label, impact, expl, zone, move = spec
            product = (svc.attrs.get("product") or "").strip()
            version = (svc.attrs.get("version") or "").strip()
            det = f"{label} on {svc.key}"
            if product:
                det += f" — {product} {version}".rstrip()
            # If we actually observed it (active), bump exploitability a notch.
            if svc.confidence is Confidence.OBSERVED and expl < Exploitability.LIKELY:
                expl = Exploitability(expl + 1)
            add(zone, Lead(zone, label, svc.key, impact, expl, move=move,
                           detail=det, confidence=svc.confidence,
                           evidence=svc.evidence[:2], source_tool="castle"))
        for cve in svc.attrs.get("vulns", []) or []:
            add(Zone.GARRISON, Lead(
                Zone.GARRISON, f"Reported vulnerable: {cve}", svc.key,
                Impact.RCE, Exploitability.POSSIBLE,
                move="Banner-derived CVE — confirm the exact build before "
                     "trusting; version strings lie.",
                detail="Passive CVE association from banner data.",
                confidence=Confidence.REPORTED, refs=[cve],
                evidence=svc.evidence[:2], source_tool="castle"))

    # Armory: obsolete TLS + weak ciphers
    for svc in graph.services:
        versions = [str(v).lower().replace(" ", "")
                    for v in (svc.attrs.get("tls_versions") or []) if v]
        obsolete = svc.attrs.get("tls_obsolete") or [
            v for v in versions if v in OBSOLETE_TLS]
        if obsolete:
            expl = (Exploitability.CONFIRMED if svc.confidence is Confidence.OBSERVED
                    else Exploitability.LIKELY)
            add(Zone.ARMORY, Lead(
                Zone.ARMORY, f"Obsolete TLS offered: {', '.join(v.upper() for v in obsolete)}",
                svc.key, Impact.DATA, expl,
                move="Downgrade/MITM candidate; pair with a network position. "
                     "Also a compliance flag.",
                confidence=svc.confidence, evidence=svc.evidence[:2],
                source_tool="castle"))
        for cipher in svc.attrs.get("tls_ciphers") or []:
            low = str(cipher).lower()
            if any(t in low for t in WEAK_CIPHER_TOKENS):
                add(Zone.ARMORY, Lead(
                    Zone.ARMORY, f"Weak cipher: {cipher}", svc.key,
                    Impact.DATA, Exploitability.POSSIBLE,
                    move="Weak suite negotiable — downgrade target.",
                    confidence=svc.confidence, source_tool="castle"))
        if svc.attrs.get("cert_expired"):
            add(Zone.ARMORY, Lead(
                Zone.ARMORY, "Expired certificate", svc.key, Impact.RECON,
                Exploitability.THEORETICAL,
                move="Signals unmonitored host — often the soft target.",
                confidence=svc.confidence, source_tool="castle"))

    # Banners: version disclosure
    versioned = [s for s in graph.services if s.attrs.get("version")]
    stacks = sorted({f"{s.attrs.get('product')} {s.attrs.get('version')}".strip()
                     for s in versioned if s.attrs.get("product")})
    if versioned:
        add(Zone.BANNERS, Lead(
            Zone.BANNERS, "Precise versions disclosed", target, Impact.RECON,
            Exploitability.LIKELY,
            move="Map each version to public CVEs/exploits before touching the "
                 "host — free target selection.",
            detail=f"{len(versioned)} service(s) advertise exact versions: "
                   + ", ".join(stacks[:8]),
            source_tool="castle"))

    # Postern: non-prod live, dangling CNAME, dead names
    for host in graph.hosts:
        frag = _matches(host.key, POSTERN_NAMES)
        if frag and host.attrs.get("resolves"):
            add(Zone.POSTERN, Lead(
                Zone.POSTERN, f"Non-prod host live ({frag})", host.key,
                Impact.FOOTHOLD, Exploitability.POSSIBLE,
                move="Non-prod is where controls are thin — debug on, stale "
                     "builds, weaker auth, test creds. Prioritise.",
                confidence=host.confidence, evidence=host.evidence[:2],
                source_tool="castle"))
        cname = host.attrs.get("cname")
        if cname and not host.attrs.get("resolves"):
            hit = next((t for t in TAKEOVER_TARGETS if cname.endswith(t)), None)
            if hit:
                add(Zone.POSTERN, Lead(
                    Zone.POSTERN, "Dangling CNAME — subdomain takeover", host.key,
                    Impact.TAKEOVER, Exploitability.LIKELY,
                    move=f"CNAME -> {cname} ({hit}) but no resolution. Claim the "
                         "backing resource to serve content from this name.",
                    confidence=host.confidence, evidence=host.evidence[:2],
                    source_tool="castle"))

    dead = [h for h in graph.hosts if h.attrs.get("resolves") is False
            and not h.attrs.get("cname")]
    if dead:
        add(Zone.POSTERN, Lead(
            Zone.POSTERN, "Decommissioned names discoverable", target,
            Impact.RECON, Exploitability.THEORETICAL,
            move="Map the estate's history; watch for re-registrable infra.",
            detail=f"{len(dead)} name(s) in CT/passive DNS no longer resolve.",
            source_tool="castle"))

    # Keep: dense origin concentration
    origin = [ip for ip in graph.ips if ip.key not in edge_ips]
    for ip in sorted(origin, key=lambda i: len(graph.services_for(i.key)),
                     reverse=True)[:5]:
        n = len(graph.services_for(ip.key))
        if n >= 5:
            add(Zone.KEEP, Lead(
                Zone.KEEP, "Dense service concentration", ip.key, Impact.FOOTHOLD,
                Exploitability.POSSIBLE,
                move=f"{n} services on one host ({ip.attrs.get('org') or '?'}). "
                     "One compromise reaches them all — high-value single target.",
                confidence=ip.confidence, source_tool="castle"))

    # Nuclei-confirmed findings
    for ep in graph.of_kind(AssetKind.ENDPOINT):
        sev = ep.attrs.get("nuclei_severity")
        if not sev:
            continue
        impact, expl = NUCLEI_IMPACT.get(sev, (Impact.RECON, Exploitability.CONFIRMED))
        tags = ep.attrs.get("nuclei_tags") or []
        zone = Zone.GARRISON
        if any(t in tags for t in ("takeover",)):
            zone, impact = Zone.POSTERN, Impact.TAKEOVER
        elif any(t in tags for t in ("ssrf", "redirect", "oast")):
            zone = Zone.SALLYPORT
        elif any(t in tags for t in ("exposure", "disclosure", "config")):
            zone, impact = Zone.POSTERN, max(impact, Impact.DATA)
        add(zone, Lead(
            zone, ep.attrs.get("nuclei_name") or ep.attrs.get("nuclei_template"),
            ep.attrs.get("matched_at") or ep.key, impact, expl,
            move="Confirmed by nuclei — validate and weaponise per template.",
            detail=f"template {ep.attrs.get('nuclei_template')} [{sev}]",
            confidence=Confidence.OBSERVED,
            refs=ep.attrs.get("nuclei_cves") or [], source_tool="nuclei"))

    # Scout's report: external intel
    for a in graph.assets.values():
        score = a.attrs.get("rf_score")
        if isinstance(score, (int, float)) and score >= 40:
            add(Zone.SCOUTS_REPORT, Lead(
                Zone.SCOUTS_REPORT, f"External risk intel (score {int(score)})",
                a.key, Impact.RECON, Exploitability.POSSIBLE,
                move="Recorded Future flags this asset — pivot on the rules "
                     "cited; it may already be compromised infrastructure.",
                detail="; ".join((a.attrs.get("rf_rules") or [])[:3]),
                confidence=a.confidence, source_tool="castle"))

    # SMB shares and looted credentials
    for svc in graph.services:
        if svc.attrs.get("product") == "SMB" or svc.attrs.get("port") == 445:
            readable = svc.attrs.get("smb_readable") or []
            shares = svc.attrs.get("smb_shares") or []
            if shares:
                impact = Impact.DATA if readable else Impact.RECON
                expl = (Exploitability.CONFIRMED if svc.confidence is Confidence.OBSERVED
                        else Exploitability.LIKELY)
                add(Zone.GARRISON, Lead(
                    Zone.GARRISON,
                    f"SMB shares exposed ({len(readable)} readable)"
                    if readable else "SMB shares enumerable", svc.key,
                    impact, expl,
                    move="Anonymous/null-session share access — mount the "
                         "readable shares and loot for creds, configs, backups."
                         if readable else "Shares listable — check each for "
                         "read access with valid or null creds.",
                    detail="readable: " + ", ".join(readable[:8]) if readable
                    else "shares: " + ", ".join(shares[:8]),
                    confidence=svc.confidence, evidence=svc.evidence[:2],
                    source_tool="smb"))

    for cred in graph.of_kind(AssetKind.CREDENTIAL):
        hi = cred.attrs.get("high_signal")
        add(Zone.GARRISON, Lead(
            Zone.GARRISON, f"Credential looted: {cred.attrs.get('label')}",
            cred.attrs.get("location", cred.key),
            Impact.CREDENTIALS,
            Exploitability.CONFIRMED if hi else Exploitability.LIKELY,
            move="Recover it from the share and test for reuse across the "
                 "estate — looted creds are the fastest lateral path.",
            detail=f"{cred.attrs.get('preview','')} "
                   f"(in {cred.attrs.get('location','')})",
            confidence=Confidence.OBSERVED, source_tool="smb"))

    # IP cameras / NVRs
    for svc in graph.services:
        vendor = svc.attrs.get("camera_vendor")
        if not vendor:
            continue
        defaults = svc.attrs.get("default_creds") or []
        has_def = bool(defaults)
        add(Zone.GARRISON, Lead(
            Zone.GARRISON, f"IP camera / NVR: {vendor}", svc.key,
            Impact.FOOTHOLD if has_def else Impact.RECON,
            Exploitability.LIKELY if has_def else Exploitability.POSSIBLE,
            move=(f"Try vendor defaults ({', '.join(defaults)}) and check the "
                  "build against known camera CVEs — these are rarely patched."
                  if has_def else "Fingerprint the exact model for known CVEs; "
                  "check for unauthenticated RTSP streams."),
            detail=f"{vendor} via {svc.attrs.get('camera_protocol')} on {svc.key}",
            confidence=svc.confidence, evidence=svc.evidence[:2],
            source_tool="cctv"))

    # mDNS / Bonjour service discovery (LAN situational awareness)
    seen_mdns: set[str] = set()
    for svc in graph.services:
        m = svc.attrs.get("mdns_service")
        if not m or m in seen_mdns:
            continue
        seen_mdns.add(m)
        kind = svc.attrs.get("device_kind") or m
        add(Zone.SCOUTS_REPORT, Lead(
            Zone.SCOUTS_REPORT, f"mDNS: {kind}", svc.attrs.get("ip", svc.key),
            Impact.RECON, Exploitability.POSSIBLE,
            move="LAN device advertising over Bonjour — maps the segment and "
                 "flags casts/printers/VNC worth a closer look.",
            detail=f"{kind} at {svc.attrs.get('ip','?')}",
            confidence=svc.confidence, source_tool="mdns"))

    # RF / proximity devices (Bluetooth, BLE, AirDrop) — The Environs
    for host in graph.hosts:
        if not host.attrs.get("rf"):
            continue
        note = host.attrs.get("note")
        add(Zone.ENVIRONS, Lead(
            Zone.ENVIRONS,
            note or f"{host.attrs.get('device_kind','RF device')} in range",
            host.attrs.get("bt_address", host.key),
            Impact.RECON, Exploitability.THEORETICAL,
            move="Physical-proximity intel for a red-team/physical engagement — "
                 "presence only; correlate with people/places, don't interact.",
            detail=host.attrs.get("bt_name", ""),
            confidence=host.confidence, source_tool="rf"))

    avenues = _assemble_avenues(zones, graph)
    return AttackMap(target=target, knowledge=knowledge, zones=zones,
                     avenues=avenues, graph=graph)


def _assemble_avenues(zones: dict[Zone, ZoneView], graph: AssetGraph) -> list[Avenue]:
    """Deterministic avenue assembly. The LLM layer, when on, rewrites the
    narratives and may propose cross-lead chains this misses."""
    avenues: list[Avenue] = []

    # Group the highest-value leads per zone into single-thrust avenues.
    for zone in [Zone.POSTERN, Zone.GARRISON, Zone.GATEHOUSE, Zone.CURTAIN_WALL,
                 Zone.SALLYPORT, Zone.ARMORY, Zone.SCOUTS_REPORT]:
        zl = sorted(zones[zone].leads, key=lambda l: -l.priority)
        if not zl:
            continue
        top = zl[:3]
        avenues.append(Avenue(
            name=f"{ZONE_LABEL[zone]} approach",
            entry_zone=zone,
            objective=top[0].impact.label,
            leads=top,
            narrative=_deterministic_narrative(zone, top),
        ))

    avenues.sort(key=lambda a: -a.score)
    return avenues


def _deterministic_narrative(zone: Zone, leads: list[Lead]) -> str:
    lead = leads[0]
    return f"{ZONE_INTENT[zone]}. Start at {lead.asset_key}: {lead.move}"
