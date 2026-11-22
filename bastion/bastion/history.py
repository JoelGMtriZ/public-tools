"""Persistent scan history — stores every completed run and its full lead set.

Uses the same SQLite file as the response cache (cfg.cache_path) but a
separate table so the two concerns don't interfere. Each run stores all lead
fields needed for later review and diffing, plus headline metadata for the
history list view.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    run_id        TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    mode          TEXT DEFAULT 'passive',
    profile       TEXT DEFAULT 'balanced',
    knowledge     TEXT DEFAULT 'black',
    lead_count    INTEGER DEFAULT 0,
    confirmed     INTEGER DEFAULT 0,
    top_impact    TEXT DEFAULT '',
    sources       TEXT DEFAULT '[]',
    leads_json    TEXT DEFAULT '[]',
    headline      TEXT DEFAULT '',
    stats_line    TEXT DEFAULT ''
);
"""


@dataclass
class RunRecord:
    run_id: str
    target: str
    started_at: float
    finished_at: float = 0.0
    mode: str = "passive"
    profile: str = "balanced"
    knowledge: str = "black"
    lead_count: int = 0
    confirmed: int = 0
    top_impact: str = ""
    sources: list[str] = field(default_factory=list)
    leads: list[dict] = field(default_factory=list)
    headline: str = ""
    stats_line: str = ""

    @property
    def started_iso(self) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(
            self.started_at, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    @property
    def duration_s(self) -> float:
        if self.finished_at and self.started_at:
            return round(self.finished_at - self.started_at, 1)
        return 0.0

    def to_meta(self) -> dict:
        """Metadata suitable for the history list (no leads)."""
        return {
            "run_id": self.run_id, "target": self.target,
            "started_at": self.started_at, "started_iso": self.started_iso,
            "finished_at": self.finished_at, "duration_s": self.duration_s,
            "mode": self.mode, "profile": self.profile, "knowledge": self.knowledge,
            "lead_count": self.lead_count, "confirmed": self.confirmed,
            "top_impact": self.top_impact, "sources": self.sources,
            "headline": self.headline, "stats_line": self.stats_line,
        }


class RunHistory:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    # ------------------------------------------------------------------ write
    def save(self, record: RunRecord) -> None:
        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO scan_history
                (run_id, target, started_at, finished_at, mode, profile, knowledge,
                 lead_count, confirmed, top_impact, sources, leads_json, headline, stats_line)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                record.run_id, record.target,
                record.started_at, record.finished_at or time.time(),
                record.mode, record.profile, record.knowledge,
                record.lead_count, record.confirmed, record.top_impact,
                json.dumps(record.sources), json.dumps(record.leads),
                record.headline, record.stats_line,
            ))

    def delete(self, run_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM scan_history WHERE run_id=?", (run_id,))
        return cur.rowcount > 0

    # ------------------------------------------------------------------ read
    def list_runs(self, limit: int = 200) -> list[RunRecord]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT run_id, target, started_at, finished_at, mode, profile, knowledge,
                       lead_count, confirmed, top_impact, sources, '' AS leads_json,
                       headline, stats_line
                FROM scan_history ORDER BY started_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [self._row(r, leads=False) for r in rows]

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._conn() as c:
            row = c.execute("""
                SELECT run_id, target, started_at, finished_at, mode, profile, knowledge,
                       lead_count, confirmed, top_impact, sources, leads_json,
                       headline, stats_line
                FROM scan_history WHERE run_id=?
            """, (run_id,)).fetchone()
        return self._row(row, leads=True) if row else None

    def runs_for_target(self, target: str, limit: int = 50) -> list[RunRecord]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT run_id, target, started_at, finished_at, mode, profile, knowledge,
                       lead_count, confirmed, top_impact, sources, '' AS leads_json,
                       headline, stats_line
                FROM scan_history WHERE target=? ORDER BY started_at DESC LIMIT ?
            """, (target, limit)).fetchall()
        return [self._row(r, leads=False) for r in rows]

    def targets(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute(
                "SELECT DISTINCT target FROM scan_history ORDER BY target")]

    @staticmethod
    def _row(row: sqlite3.Row, *, leads: bool) -> RunRecord:
        return RunRecord(
            run_id=row["run_id"], target=row["target"],
            started_at=row["started_at"] or 0.0,
            finished_at=row["finished_at"] or 0.0,
            mode=row["mode"] or "passive", profile=row["profile"] or "balanced",
            knowledge=row["knowledge"] or "black",
            lead_count=row["lead_count"] or 0, confirmed=row["confirmed"] or 0,
            top_impact=row["top_impact"] or "",
            sources=json.loads(row["sources"] or "[]"),
            leads=json.loads(row["leads_json"] or "[]") if leads else [],
            headline=row["headline"] or "", stats_line=row["stats_line"] or "",
        )
