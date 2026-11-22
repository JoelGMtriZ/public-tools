"""Three-way diff between two scan runs.

Leads are matched by fingerprint (zone|asset|title — stable across runs for the
same finding). The diff surfaces:

  NEW       — present in B (newer), absent in A (older)
  RESOLVED  — present in A, absent in B (no longer detected)
  CHANGED   — fingerprint in both, but impact / exploitability / priority differ

Unchanged leads are counted but not listed (they'd just be noise).
"""
from __future__ import annotations

from dataclasses import dataclass
from .history import RunRecord


# Fields that determine whether a lead has "changed" between runs.
_CHANGE_FIELDS = ("impact", "exploitability", "priority")


@dataclass
class LeadDiff:
    run_a: RunRecord          # older / baseline
    run_b: RunRecord          # newer / current
    new_leads: list[dict]     # in B not in A  — sorted by priority desc
    resolved_leads: list[dict]  # in A not in B
    changed_leads: list[dict]   # in both; each entry has a "changes" sub-dict
    unchanged_count: int

    # ---------------------------------------------------------------- summary
    @property
    def has_changes(self) -> bool:
        return bool(self.new_leads or self.resolved_leads or self.changed_leads)

    @property
    def summary(self) -> str:
        parts = []
        if self.new_leads:
            parts.append(f"{len(self.new_leads)} new")
        if self.resolved_leads:
            parts.append(f"{len(self.resolved_leads)} resolved")
        if self.changed_leads:
            parts.append(f"{len(self.changed_leads)} changed")
        if self.unchanged_count:
            parts.append(f"{self.unchanged_count} unchanged")
        return " · ".join(parts) if parts else "no differences"

    def to_dict(self) -> dict:
        return {
            "run_a": self.run_a.to_meta(),
            "run_b": self.run_b.to_meta(),
            "summary": self.summary,
            "new_leads": self.new_leads,
            "resolved_leads": self.resolved_leads,
            "changed_leads": self.changed_leads,
            "unchanged_count": self.unchanged_count,
        }


def diff_runs(run_a: RunRecord, run_b: RunRecord) -> LeadDiff:
    """Compare run_a (older/baseline) against run_b (newer/current).

    Both records must have their leads populated (call history.get_run, not
    list_runs, which omits leads for performance).
    """
    idx_a = {l["fingerprint"]: l for l in run_a.leads if l.get("fingerprint")}
    idx_b = {l["fingerprint"]: l for l in run_b.leads if l.get("fingerprint")}

    fps_a, fps_b = set(idx_a), set(idx_b)

    new_leads = _sort([idx_b[fp] for fp in fps_b - fps_a])
    resolved_leads = _sort([idx_a[fp] for fp in fps_a - fps_b])

    changed_leads: list[dict] = []
    unchanged = 0
    for fp in fps_a & fps_b:
        a, b = idx_a[fp], idx_b[fp]
        changes: dict[str, dict] = {}
        for field in _CHANGE_FIELDS:
            va, vb = a.get(field), b.get(field)
            if va != vb:
                changes[field] = {"from": va, "to": vb}
        if changes:
            changed_leads.append({**b, "changes": changes, "prev": {
                f: a.get(f) for f in _CHANGE_FIELDS}})
        else:
            unchanged += 1

    changed_leads = _sort(changed_leads)
    return LeadDiff(
        run_a=run_a, run_b=run_b,
        new_leads=new_leads, resolved_leads=resolved_leads,
        changed_leads=changed_leads, unchanged_count=unchanged,
    )


def _sort(leads: list[dict]) -> list[dict]:
    return sorted(leads, key=lambda l: -(l.get("priority") or 0))
