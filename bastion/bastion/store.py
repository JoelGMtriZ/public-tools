"""Persistence: an HTTP response cache and a run history for drift detection.

The cache exists to protect your API quota — passive sources are rate limited
far below what the pipeline could consume. The run history is what makes the
longitudinal analysis possible: the shape of an estate changing over weeks is a
stronger signal than any single snapshot.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    source     TEXT NOT NULL,
    key        TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (source, key)
);
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    target     TEXT NOT NULL,
    mode       TEXT NOT NULL,
    started_at REAL NOT NULL,
    ended_at   REAL,
    asset_count INTEGER DEFAULT 0,
    score      REAL
);
CREATE TABLE IF NOT EXISTS run_assets (
    run_id  TEXT NOT NULL,
    kind    TEXT NOT NULL,
    key     TEXT NOT NULL,
    attrs   TEXT NOT NULL,
    sources TEXT NOT NULL,
    PRIMARY KEY (run_id, key)
);
CREATE TABLE IF NOT EXISTS run_findings (
    run_id      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    zone        TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    title       TEXT NOT NULL,
    asset_key   TEXT NOT NULL,
    PRIMARY KEY (run_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target, started_at DESC);
"""


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- response cache -------------------------------------------------
    def cache_get(self, source: str, key: str, ttl: int) -> Any | None:
        row = self._conn.execute(
            "SELECT payload, fetched_at FROM cache WHERE source=? AND key=?",
            (source, _hash(key)),
        ).fetchone()
        if row is None:
            return None
        if time.time() - row["fetched_at"] > ttl:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return None

    def cache_put(self, source: str, key: str, payload: Any) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (source, key, payload, fetched_at) "
            "VALUES (?,?,?,?)",
            (source, _hash(key), json.dumps(payload, default=str), time.time()),
        )
        self._conn.commit()

    def cache_purge(self, older_than_seconds: int = 0) -> int:
        cur = self._conn.execute(
            "DELETE FROM cache WHERE fetched_at < ?",
            (time.time() - older_than_seconds,),
        )
        self._conn.commit()
        return cur.rowcount

    # ---- run history ----------------------------------------------------
    def start_run(self, run_id: str, target: str, mode: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, target, mode, started_at) "
            "VALUES (?,?,?,?)",
            (run_id, target, mode, time.time()),
        )
        self._conn.commit()

    def finish_run(self, run_id: str, assets: Iterable, findings: Iterable,
                   score: float) -> None:
        assets = list(assets)
        self._conn.executemany(
            "INSERT OR REPLACE INTO run_assets (run_id, kind, key, attrs, sources) "
            "VALUES (?,?,?,?,?)",
            [(run_id, a.kind.value, a.key,
              json.dumps(a.attrs, default=str), json.dumps(sorted(a.sources)))
             for a in assets],
        )
        self._conn.executemany(
            "INSERT OR REPLACE INTO run_findings "
            "(run_id, fingerprint, zone, severity, title, asset_key) VALUES (?,?,?,?,?,?)",
            [(run_id, f.fingerprint, f.zone.value, int(f.severity),
              f.title, f.asset_key) for f in findings],
        )
        self._conn.execute(
            "UPDATE runs SET ended_at=?, asset_count=?, score=? WHERE run_id=?",
            (time.time(), len(assets), score, run_id),
        )
        self._conn.commit()

    def previous_run(self, target: str, before_run_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT run_id FROM runs WHERE target=? AND run_id!=? AND ended_at IS NOT NULL "
            "ORDER BY started_at DESC LIMIT 1",
            (target, before_run_id),
        ).fetchone()
        return row["run_id"] if row else None

    def diff_assets(self, run_id: str, prior_run_id: str) -> dict[str, list[str]]:
        """What appeared and what vanished since the prior run."""
        def keys(rid: str) -> set[str]:
            return {r["key"] for r in self._conn.execute(
                "SELECT key FROM run_assets WHERE run_id=?", (rid,))}
        now, then = keys(run_id), keys(prior_run_id)
        return {"appeared": sorted(now - then), "vanished": sorted(then - now)}

    def score_history(self, target: str, limit: int = 30) -> list[tuple[float, float]]:
        rows = self._conn.execute(
            "SELECT started_at, score FROM runs WHERE target=? AND score IS NOT NULL "
            "ORDER BY started_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        return [(r["started_at"], r["score"]) for r in reversed(rows)]
