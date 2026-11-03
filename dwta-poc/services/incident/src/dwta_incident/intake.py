"""Incident intake (B9): incidents/inbox/*.json -> incidents table -> review once a restore time is known."""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from dwta_core.config import load_config
from dwta_core.fileio import append_jsonl
from dwta_core.timeutil import parse_iso
from dwta_ledger.common import publish_alerts

from .engine import Engine

log = logging.getLogger("incident.intake")
REQUIRED = ("incident_id", "detected_sim_ts", "volumes")


class IncidentError(ValueError):
    pass


def check_restore_time(restore: datetime, detected: datetime) -> None:
    """INC-06: restore time must be before detection and within max_window_days."""
    max_days = int(load_config("ranking").data.get("max_window_days", 90))
    if restore >= detected:
        raise IncidentError(f"restore time {restore.isoformat()} is not before detection {detected.isoformat()}")
    if detected - restore > timedelta(days=max_days):
        raise IncidentError(f"restore time is more than {max_days} days before detection")


def upsert(conn: psycopg.Connection, rec: dict[str, Any]) -> tuple[str, bool]:
    """Returns (incident_id, ready_for_review)."""
    if rec.get("schema") not in ("dwta.incident/v1", None):
        raise IncidentError(f"unsupported schema {rec.get('schema')!r}")
    missing = [k for k in REQUIRED if not rec.get(k)]
    if missing:
        raise IncidentError(f"missing fields {missing}")
    iid = rec["incident_id"]
    detected = parse_iso(rec["detected_sim_ts"])
    restore = parse_iso(rec["restore_time_sim_ts"]) if rec.get("restore_time_sim_ts") else None
    existing = conn.execute("SELECT state FROM incidents WHERE incident_id = %s", (iid,)).fetchone()
    if existing and existing["state"] == "finalized":
        raise IncidentError(f"incident {iid} is finalized; update ignored")
    try:
        if restore:
            check_restore_time(restore, detected)
    except IncidentError as e:
        conn.execute(
            "INSERT INTO incidents (incident_id, source, kind, detected_sim_ts, \"user\", client_ip, client_name, volumes,"
            " description, state, reject_reason) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'rejected',%s) "
            "ON CONFLICT (incident_id) DO UPDATE SET state = 'rejected', reject_reason = EXCLUDED.reject_reason",
            (iid, rec.get("source", "unknown"), rec.get("kind", "ransomware"), detected, rec.get("user"),
             rec.get("client_ip"), rec.get("client_name"), rec["volumes"], rec.get("description"), str(e)))
        raise
    state = "under_review" if restore else "awaiting_restore_time"
    conn.execute(
        "INSERT INTO incidents (incident_id, source, kind, detected_sim_ts, \"user\", client_ip, client_name, volumes,"
        " restore_time_sim_ts, description, state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (incident_id) DO UPDATE SET restore_time_sim_ts = COALESCE(EXCLUDED.restore_time_sim_ts,"
        " incidents.restore_time_sim_ts), reject_reason = NULL, state = CASE WHEN COALESCE(EXCLUDED.restore_time_sim_ts,"
        " incidents.restore_time_sim_ts) IS NULL THEN 'awaiting_restore_time' ELSE 'under_review' END",
        (iid, rec.get("source", "unknown"), rec.get("kind", "ransomware"), detected, rec.get("user"), rec.get("client_ip"),
         rec.get("client_name"), rec["volumes"], restore, rec.get("description"), state))
    ready = conn.execute("SELECT restore_time_sim_ts FROM incidents WHERE incident_id = %s", (iid,)).fetchone()
    return iid, ready["restore_time_sim_ts"] is not None


def set_restore_time(conn: psycopg.Connection, iid: str, restore: datetime) -> None:
    inc = conn.execute("SELECT * FROM incidents WHERE incident_id = %s", (iid,)).fetchone()
    if inc is None:
        raise IncidentError(f"unknown incident {iid}")
    if inc["state"] == "finalized":
        raise IncidentError(f"incident {iid} is finalized")
    check_restore_time(restore, inc["detected_sim_ts"])
    conn.execute("UPDATE incidents SET restore_time_sim_ts = %s, state = 'under_review', reject_reason = NULL "
                 "WHERE incident_id = %s", (restore, iid))


def process_inbox(conn: psycopg.Connection, incidents_dir: Path, engine: Engine) -> int:
    n = 0
    for f in sorted((incidents_dir / "inbox").glob("*.json")):
        dest = "processed"
        try:
            rec = json.loads(f.read_text())
            with conn.transaction():
                iid, ready = upsert(conn, rec)
            log.info("incident received", extra={"fields": {"incident_id": iid, "ready": ready}})
            if ready:
                out = engine.review(iid)
                publish_alerts(engine.run_dir, "incident", [out["alert"]] if out["alert"] else [])
                lists = {m: len(v) for m, v in out["doc"]["modes"].items()}
                log.info("review list ready", extra={"fields": {"incident_id": iid, "listed": lists,
                                                                 "incomplete": out["doc"]["incomplete"]}})
        except (IncidentError, json.JSONDecodeError, KeyError) as e:
            dest = "rejected"
            append_jsonl(incidents_dir / "rejected" / f"{f.stem}.reason.jsonl", {"file": f.name, "reason": str(e)})
            log.warning("incident rejected", extra={"fields": {"file": f.name, "reason": str(e)}})
        target = incidents_dir / dest / f.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(f), target)
        n += 1
    return n
