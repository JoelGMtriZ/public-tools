"""LLM attack-path synthesis — the scout's verbal report to the general.

Off by default. The deterministic AttackMap is complete without it; this layer
only rewrites avenue narratives and proposes cross-lead chains a rule engine
would not pre-encode. It never produces a finding and never gates one — it reads
already-structured leads and returns prose plus optional chain suggestions.

Talks to any OpenAI-compatible /chat/completions endpoint (Ollama, llama.cpp,
vLLM), so a local ~30-40B MoE serves fine. On any failure it degrades silently
to the deterministic narratives already on the map.
"""
from __future__ import annotations

import json
import logging

from .castle import AttackMap
from .config import LLMConfig
from .models import Avenue

log = logging.getLogger("bastion.synth")

SYSTEM = (
    "You are a senior offensive-security operator writing the reconnaissance "
    "brief that another operator will act on. You are given structured recon "
    "leads from an authorised engagement. Be concrete and terse. Prioritise by "
    "what yields access fastest. Never invent hosts, versions, or findings not "
    "present in the input. If you propose a chain, every step must reference a "
    "lead that exists in the input."
)


def _leads_payload(amap: AttackMap, cap: int = 40) -> list[dict]:
    return [{
        "id": l.fingerprint,
        "zone": l.zone.value,
        "title": l.title,
        "asset": l.asset_key,
        "impact": l.impact.label,
        "exploitability": l.exploitability.label,
        "priority": l.priority,
        "move": l.move,
        "refs": l.refs,
    } for l in amap.leads[:cap]]


def _brief_prompt(amap: AttackMap) -> str:
    return (
        f"Target: {amap.target}\nKnowledge: {amap.knowledge}-box\n"
        f"Leads (ranked, priority = impact x exploitability):\n"
        f"{json.dumps(_leads_payload(amap), indent=1)}\n\n"
        "Return JSON only, no prose outside it, with this shape:\n"
        '{"summary": "<=3 sentences: where to attack first and why", '
        '"avenues": [{"name": "...", "objective": "...", '
        '"steps": ["lead id", "lead id"], "narrative": "2-4 sentences"}], '
        '"chains": [{"hypothesis": "...", "steps": ["lead id", ...], '
        '"rationale": "..."}]}'
    )


async def synthesise(amap: AttackMap, cfg: LLMConfig, http) -> dict | None:
    """Return {'summary','avenues','chains','model'} or None if unavailable."""
    if not cfg.enabled:
        return None
    body = {
        "model": cfg.model,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": _brief_prompt(amap)}],
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "stream": False,
    }
    try:
        data = await http.post_json(
            "llm", f"{cfg.base_url.rstrip('/')}/chat/completions",
            json_body=body,
            headers={"Authorization": f"Bearer {cfg.api_key}"},
            ttl=0)
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM synthesis failed: %s", exc)
        return None
    if not data:
        log.warning("LLM endpoint unreachable at %s — using deterministic "
                    "narratives", cfg.base_url)
        return None

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None

    parsed = _extract_json(content)
    if not parsed:
        # Model returned prose; keep it as the summary rather than discard.
        return {"summary": content.strip()[:800], "avenues": [], "chains": [],
                "model": cfg.model}
    parsed["model"] = cfg.model
    return parsed


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def apply_synthesis(amap: AttackMap, synth: dict) -> None:
    """Fold LLM narratives back onto the map's avenues, and attach chains.

    Matching is by lead id so the model cannot introduce assets that do not
    exist — an id it invents simply matches nothing and is dropped.
    """
    by_id = {l.fingerprint: l for l in amap.leads}
    llm_avenues: list[Avenue] = []
    for a in synth.get("avenues", []) or []:
        steps = [by_id[s] for s in a.get("steps", []) if s in by_id]
        if not steps:
            continue
        llm_avenues.append(Avenue(
            name=a.get("name", "Avenue"),
            entry_zone=steps[0].zone,
            objective=a.get("objective", steps[0].impact.label),
            leads=steps,
            narrative=a.get("narrative", ""),
            llm_written=True))
    if llm_avenues:
        # LLM avenues lead; keep any deterministic ones it didn't cover.
        covered = {l.fingerprint for av in llm_avenues for l in av.leads}
        kept = [av for av in amap.avenues
                if not all(l.fingerprint in covered for l in av.leads)]
        amap.avenues = sorted(llm_avenues, key=lambda a: -a.score) + kept

    # Validate chains the same way.
    valid_chains = []
    for c in synth.get("chains", []) or []:
        steps = [by_id[s] for s in c.get("steps", []) if s in by_id]
        if len(steps) >= 2:
            valid_chains.append({"hypothesis": c.get("hypothesis", ""),
                                 "steps": [l.fingerprint for l in steps],
                                 "rationale": c.get("rationale", "")})
    synth["chains"] = valid_chains
