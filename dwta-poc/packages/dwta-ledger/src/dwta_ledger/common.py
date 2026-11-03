"""Helpers shared by the writer services: alerts (LED-04) and journal consumer offsets."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg
from dwta_core.fileio import append_jsonl
from dwta_core.timeutil import iso
from psycopg.types.json import Jsonb


def alert_id(kind: str, mode: str, artifact_id: int | None, incident_id: str | None, rule_ids: list[str]) -> str:
    key = "|".join([kind, mode, str(artifact_id or ""), incident_id or "", ",".join(sorted(rule_ids))])
    return hashlib.sha256(key.encode()).hexdigest()


def insert_alert(conn: psycopg.Connection, *, kind: str, severity: str, mode: str, rule_ids: list[str],
                 reasons: Any, sim_ts: datetime | None, artifact_id: int | None = None,
                 incident_id: str | None = None) -> dict[str, Any] | None:
    """Inserts once (deterministic id). Returns the alert if new, else None (a replay)."""
    aid = alert_id(kind, mode, artifact_id, incident_id, rule_ids)
    row = conn.execute(
        "INSERT INTO alerts (alert_id, kind, severity, mode, artifact_id, incident_id, rule_ids, reasons, sim_ts) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (alert_id) DO NOTHING RETURNING alert_id",
        (aid, kind, severity, mode, artifact_id, incident_id, rule_ids, Jsonb(reasons), sim_ts),
    ).fetchone()
    if row is None:
        return None
    return {"alert_id": aid, "kind": kind, "severity": severity, "mode": mode, "artifact_id": artifact_id,
            "incident_id": incident_id, "rule_ids": rule_ids, "reasons": reasons,
            "sim_ts": iso(sim_ts) if sim_ts else None}


def publish_alerts(run_dir: Path, service: str, alerts: list[dict[str, Any]]) -> None:
    """After commit: mirror new alerts to run/alerts/<service>.jsonl (one writer per file)."""
    for a in alerts:
        append_jsonl(run_dir / "alerts" / f"{service}.jsonl", a)


def get_offset(conn: psycopg.Connection, consumer: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM consumer_offsets WHERE consumer = %s", (consumer,)).fetchone()
    return row or {"consumer": consumer, "segment": "", "line": 0, "high_water_ts": None, "high_water_sim_ts": None}


def set_offset(conn: psycopg.Connection, consumer: str, segment: str, line: int,
               high_water_ts: datetime | None, high_water_sim_ts: datetime | None) -> None:
    conn.execute(
        "INSERT INTO consumer_offsets (consumer, segment, line, high_water_ts, high_water_sim_ts, updated_at) "
        "VALUES (%s,%s,%s,%s,%s, now()) ON CONFLICT (consumer) DO UPDATE SET segment = EXCLUDED.segment, "
        "line = EXCLUDED.line, high_water_ts = COALESCE(EXCLUDED.high_water_ts, consumer_offsets.high_water_ts), "
        "high_water_sim_ts = COALESCE(EXCLUDED.high_water_sim_ts, consumer_offsets.high_water_sim_ts), updated_at = now()",
        (consumer, segment, line, high_water_ts, high_water_sim_ts),
    )
