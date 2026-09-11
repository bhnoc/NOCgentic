"""
Findings store: SQLite, one file, WAL mode.

Why SQLite: the service runs as one container on one box, writes are one row
set per upload, and reads are analyst look-ups. A named volume is the whole
backup story. Every SQL statement lives in this module, so swapping to
PostgreSQL is a rewrite of one file, not of the service.

A fresh connection is opened per call (the same pattern athena_client uses for
boto3): nothing is cached across threads, and the FastAPI threadpool can call
in from any worker.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    classifier_mode TEXT NOT NULL,
    model           TEXT,
    source_files    TEXT NOT NULL,   -- JSON list of {name, log_type, bytes, sha256}
    event_count     INTEGER NOT NULL,
    cluster_count   INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    summary_json    TEXT NOT NULL,
    metadata_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id      TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    finding_id       TEXT NOT NULL,
    host             TEXT NOT NULL,
    destination      TEXT NOT NULL,
    service_id       TEXT NOT NULL,
    service_name     TEXT NOT NULL,
    behavior         TEXT NOT NULL,
    confidence       REAL NOT NULL,
    confidence_level TEXT NOT NULL,
    severity         TEXT NOT NULL,
    classifier_mode  TEXT NOT NULL,
    first_seen       TEXT,
    last_seen        TEXT,
    finding_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS findings_service ON findings(service_id);
CREATE INDEX IF NOT EXISTS analyses_created ON analyses(created_at);
"""

SEVERITIES = ("low", "medium", "high", "critical")


class FindingsStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── writes ───────────────────────────────────────────────────────────────

    def save_analysis(self, analysis: dict[str, Any]) -> None:
        """Persist one analysis and its findings atomically."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO analyses (id, created_at, classifier_mode, model, source_files, "
                "event_count, cluster_count, duration_ms, summary_json, metadata_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    analysis["analysis_id"],
                    analysis["created_at"],
                    analysis["classifier"]["mode"],
                    analysis["classifier"].get("model"),
                    json.dumps(analysis["source_files"]),
                    analysis["event_count"],
                    analysis["cluster_count"],
                    analysis["duration_ms"],
                    json.dumps(analysis["summary"]),
                    json.dumps(analysis["metadata"]),
                ),
            )
            conn.executemany(
                "INSERT INTO findings (analysis_id, finding_id, host, destination, service_id, "
                "service_name, behavior, confidence, confidence_level, severity, classifier_mode, "
                "first_seen, last_seen, finding_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        analysis["analysis_id"],
                        f["finding_id"],
                        f["host"],
                        f["destination"],
                        f["service_id"],
                        f["service_name"],
                        f["behavior_classification"],
                        float(f["confidence"]),
                        f["confidence_level"],
                        f["severity"],
                        f["classifier_mode"],
                        (f.get("timeline") or {}).get("first_seen"),
                        (f.get("timeline") or {}).get("last_seen"),
                        json.dumps(f),
                    )
                    for f in analysis["findings"]
                ],
            )

    # ── reads ────────────────────────────────────────────────────────────────

    @staticmethod
    def _analysis_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "analysis_id": row["id"],
            "created_at": row["created_at"],
            "classifier": {"mode": row["classifier_mode"], "model": row["model"]},
            "source_files": json.loads(row["source_files"]),
            "event_count": row["event_count"],
            "cluster_count": row["cluster_count"],
            "duration_ms": row["duration_ms"],
            "summary": json.loads(row["summary_json"]),
            "metadata": json.loads(row["metadata_json"]),
        }

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if row is None:
                return None
            out = self._analysis_row(row)
            out["findings"] = [
                json.loads(r["finding_json"])
                for r in conn.execute(
                    "SELECT finding_json FROM findings WHERE analysis_id = ? ORDER BY id",
                    (analysis_id,),
                )
            ]
            return out

    def list_analyses(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM analyses ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._analysis_row(r) for r in rows]

    def query_findings(
        self,
        host: str | None = None,
        severity: str | None = None,
        min_severity: str | None = None,
        service_id: str | None = None,
        min_confidence: float | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Findings across analyses, newest analysis first, then by severity."""
        where: list[str] = []
        args: list[Any] = []
        if host:
            where.append("f.host = ?")
            args.append(host)
        if severity:
            where.append("f.severity = ?")
            args.append(severity)
        if min_severity and min_severity in SEVERITIES:
            allowed = SEVERITIES[SEVERITIES.index(min_severity):]
            where.append(f"f.severity IN ({','.join('?' * len(allowed))})")
            args.extend(allowed)
        if service_id:
            where.append("f.service_id = ?")
            args.append(service_id)
        if min_confidence is not None:
            where.append("f.confidence >= ?")
            args.append(float(min_confidence))
        if since:
            where.append("a.created_at >= ?")
            args.append(since)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        sql = (
            "SELECT f.finding_json, f.analysis_id, a.created_at FROM findings f "
            "JOIN analyses a ON a.id = f.analysis_id "
            f"{clause} ORDER BY a.created_at DESC, "
            "CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, "
            "f.confidence DESC LIMIT ?"
        )
        args.append(limit)
        with self._connect() as conn:
            out = []
            for r in conn.execute(sql, args):
                f = json.loads(r["finding_json"])
                f["analysis_id"] = r["analysis_id"]
                f["analysis_created_at"] = r["created_at"]
                out.append(f)
            return out

    def counts(self) -> dict[str, int]:
        with self._connect() as conn:
            analyses = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            return {"analyses": analyses, "findings": findings}
