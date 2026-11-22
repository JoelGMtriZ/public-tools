"""Optional local-LLM bootstrap.

If the operator wants synthesis but has no endpoint configured, Bastion can set
up a local one: detect Ollama, offer to install it, and pull a right-sized
model. This is strictly opt-in (`--llm-setup`) and consent-gated at every step —
a security tool should never silently pipe a remote script into a shell or
download gigabytes without asking.

Model choice is a deliberate compromise. The synthesis task is reasoning over
already-structured leads with short output — it does NOT need the model to know
CVEs (nuclei does), so a small instruct model does the job. We default to the
lightest useful tier and let the operator scale up if they have the VRAM.
"""
from __future__ import annotations

import asyncio
import shutil
import sys

import httpx

# Tiered recommendations. Values are Ollama tags; sizes are approximate Q4
# on-disk / resident footprints. The task is short-context reasoning + JSON, so
# even the small tier is serviceable; the MoE tier gives the best quality per
# token because only a few billion parameters activate per pass.
MODEL_TIERS = {
    "min":     ("llama3.1:8b",       "~5 GB",  "CPU-friendly / 8 GB RAM; safe all-rounder"),
    "small":   ("qwen3:8b",          "~5 GB",  "8 GB VRAM; strong reasoning for its size"),
    "balanced":("gpt-oss:20b",       "~13 GB", "16 GB VRAM; small MoE, adjustable reasoning"),
    "moe":     ("qwen3:30b-a3b",     "~18 GB", "24 GB VRAM; 30B total / ~3B active — 7B-class speed"),
}
DEFAULT_TIER = "small"

OLLAMA_INSTALL = "curl -fsSL https://ollama.com/install.sh | sh"


def ollama_on_path() -> str | None:
    return shutil.which("ollama")


async def ollama_alive(base_url: str, timeout: float = 3.0) -> bool:
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(f"{root}/api/tags")
            return r.status_code == 200
    except (httpx.HTTPError, OSError):
        return False


async def list_models(base_url: str) -> list[str]:
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"{root}/api/tags")
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
    except (httpx.HTTPError, OSError, KeyError):
        return []


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        print(f"  {prompt} [auto-yes]")
        return True
    try:
        return input(f"  {prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def recommend(tier: str | None) -> tuple[str, str, str]:
    return MODEL_TIERS.get(tier or DEFAULT_TIER, MODEL_TIERS[DEFAULT_TIER])


async def ensure_ollama(base_url: str, *, tier: str | None = None,
                        assume_yes: bool = False) -> str | None:
    """Ensure a local model is reachable; return the model tag to use, or None.

    Prints exactly what it will do and asks before installing anything or
    downloading weights.
    """
    model, size, why = recommend(tier)

    if await ollama_alive(base_url):
        have = await list_models(base_url)
        if any(m.split(":")[0] == model.split(":")[0] for m in have):
            print(f"  Ollama is up and '{model}' is present.")
            return next(m for m in have
                        if m.split(":")[0] == model.split(":")[0])
        print(f"  Ollama is up at {base_url} but '{model}' is not pulled.")
        if _confirm(f"Pull {model} ({size}, {why})?", assume_yes):
            return await _pull(model)
        return have[0] if have else None

    # Ollama not answering. Is the binary at least installed?
    if not ollama_on_path():
        print("  Ollama is not installed. Bastion can install it with the "
              "official script:")
        print(f"      {OLLAMA_INSTALL}")
        print("  Review that script yourself if you prefer — piping a remote "
              "script to a shell")
        print("  on an engagement box is a real supply-chain decision.")
        if not _confirm("Run the official Ollama install now?", assume_yes):
            print("  Skipping install. Install Ollama yourself, then re-run "
                  "with --llm.")
            return None
        if not await _install_ollama():
            return None

    # Binary present but service down — start it.
    print("  Starting `ollama serve` in the background...")
    try:
        proc = await asyncio.create_subprocess_shell(
            "ollama serve", stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        for _ in range(20):
            await asyncio.sleep(0.5)
            if await ollama_alive(base_url):
                break
    except OSError as exc:
        print(f"  Could not start ollama: {exc}")
        return None

    if not await ollama_alive(base_url):
        print("  Ollama did not come up. Start it manually: `ollama serve`.")
        return None

    if _confirm(f"Pull {model} ({size}, {why})?", assume_yes):
        return await _pull(model)
    return None


async def _install_ollama() -> bool:
    print("  Installing Ollama...")
    proc = await asyncio.create_subprocess_shell(OLLAMA_INSTALL)
    await proc.wait()
    ok = proc.returncode == 0 and ollama_on_path() is not None
    print("  Ollama installed." if ok else "  Ollama install failed.")
    return ok


async def _pull(model: str) -> str | None:
    print(f"  Pulling {model} (this downloads several GB once)...")
    proc = await asyncio.create_subprocess_exec("ollama", "pull", model)
    await proc.wait()
    if proc.returncode == 0:
        print(f"  {model} ready.")
        return model
    print(f"  Failed to pull {model}.")
    return None


def print_tiers() -> None:
    print("  Local model tiers (pick with --llm-tier):")
    for tier, (model, size, why) in MODEL_TIERS.items():
        mark = " (default)" if tier == DEFAULT_TIER else ""
        print(f"    {tier:9} {model:16} {size:7} {why}{mark}")
