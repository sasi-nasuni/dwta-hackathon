"""Feed matcher (B8): feeds/inbox -> feed_entries -> one indexed join against artifacts. Never reads files."""

from __future__ import annotations

import csv
import io
import os
import re
import shutil
import signal
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from dwta_core import log as dlog
from dwta_core.config import load_config
from dwta_core.fileio import append_jsonl
from dwta_ledger.common import get_offset, insert_alert, publish_alerts, set_offset
from dwta_ledger.db import connect
from dwta_ledger.migrate import check_schema

SHA = re.compile(r"^[0-9a-f]{64}$")
CONSUMER = "matcher"
COLUMNS = ("first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess",
           "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh")


def parse_feed(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """MalwareBazaar CSV export format (FEED-01). Returns (rows, rejects)."""
    rows, rejects = [], []
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    for n, rec in enumerate(csv.reader(io.StringIO("\n".join(lines))), 1):
        if len(rec) < 2:
            rejects.append({"row": n, "reason": "too few columns"})
            continue
        d = dict(zip(COLUMNS, (v.strip() for v in rec), strict=False))
        sha = d["sha256_hash"].lower()
        if not SHA.match(sha):
            rejects.append({"row": n, "reason": "bad sha256", "value": d["sha256_hash"][:80]})
            continue
        try:
            seen = datetime.strptime(d["first_seen_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            seen = None
        rows.append({"sha256": sha, "first_seen": seen, "signature": d.get("signature"), "file_name": d.get("file_name"),
                     "reporter": d.get("reporter")})
    return rows, rejects


def ingest(conn: psycopg.Connection, feed_id: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Upserts entries and matches them; returns new alerts. Idempotent (MAT-05)."""
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS feed_in (sha256 CHAR(64), first_seen TIMESTAMPTZ, signature TEXT, "
                 "file_name TEXT, reporter TEXT) ON COMMIT DELETE ROWS")
    with conn.cursor().copy("COPY feed_in (sha256, first_seen, signature, file_name, reporter) FROM STDIN") as cp:
        for r in rows:
            cp.write_row((r["sha256"], r["first_seen"], r["signature"], r["file_name"], r["reporter"]))
    conn.execute("INSERT INTO feed_entries (feed_id, sha256, first_seen_sim, signature, file_name, reporter) "
                 "SELECT DISTINCT ON (sha256) %s, sha256, first_seen, signature, file_name, reporter FROM feed_in "
                 "ON CONFLICT DO NOTHING", (feed_id,))
    matches = conn.execute(
        "INSERT INTO feed_matches (artifact_id, sha256, feed_id, matched_sim_ts) "
        "SELECT a.artifact_id, a.sha256, e.feed_id, e.first_seen_sim FROM feed_entries e "
        "JOIN artifacts a ON a.sha256 = e.sha256 WHERE e.feed_id = %s "
        "ON CONFLICT (artifact_id, sha256) DO NOTHING RETURNING match_id, artifact_id, sha256, feed_id, matched_sim_ts",
        (feed_id,)).fetchall()
    return _alerts(conn, matches, "feed published", "FEED-MATCH")


def reverse_match(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """MAT-04 / R-W5: new artifacts whose hash is already known-bad."""
    hw = int(get_offset(conn, CONSUMER)["line"])
    top = conn.execute("SELECT coalesce(max(artifact_id), 0) AS m FROM artifacts").fetchone()["m"]
    if top <= hw:
        return []
    matches = conn.execute(
        "INSERT INTO feed_matches (artifact_id, sha256, feed_id, matched_sim_ts) "
        "SELECT DISTINCT ON (a.artifact_id) a.artifact_id, a.sha256, e.feed_id, a.sim_ts FROM artifacts a "
        "JOIN feed_entries e ON e.sha256 = a.sha256 WHERE a.artifact_id > %s AND a.artifact_id <= %s "
        "ORDER BY a.artifact_id, e.feed_id ON CONFLICT (artifact_id, sha256) DO NOTHING "
        "RETURNING match_id, artifact_id, sha256, feed_id, matched_sim_ts", (hw, top)).fetchall()
    set_offset(conn, CONSUMER, "artifacts", top, None, None)
    return _alerts(conn, matches, "known-bad hash at write time", "R-W5")


def _alerts(conn: psycopg.Connection, matches: list[dict[str, Any]], why: str, rule: str) -> list[dict[str, Any]]:
    """Severity comes from rules.toml (CLS-09: rule severities are configuration, not code)."""
    severity = load_config("rules").data["rule"][rule]["severity"]
    out = []
    for m in matches:
        art = conn.execute("SELECT volume, path, \"user\", client_ip::text AS ip, sim_ts FROM artifacts WHERE artifact_id = %s",
                           (m["artifact_id"],)).fetchone()
        a = insert_alert(conn, kind="feed_match", severity=severity, mode="both", rule_ids=[rule],
                         reasons=[{"why": why, "feed_id": m["feed_id"], "sha256": m["sha256"], "match_id": m["match_id"],
                                   "volume": art["volume"], "path": art["path"], "written_by": art["user"],
                                   "written_from": art["ip"]}],
                         sim_ts=m["matched_sim_ts"], artifact_id=m["artifact_id"])
        if a:
            out.append(a)
    return out


def process_inbox(conn: psycopg.Connection, feeds: Path, run_dir: Path, log) -> int:
    n = 0
    for f in sorted((feeds / "inbox").glob("*.csv")):
        feed_id = f.stem
        rows, rejects = parse_feed(f.read_text(errors="replace"))
        with conn.transaction():
            alerts = ingest(conn, feed_id, rows) if rows else []
        publish_alerts(run_dir, CONSUMER, alerts)
        for r in rejects:
            append_jsonl(feeds / "rejected" / f"{feed_id}.rejects.jsonl", r)
        dest = feeds / ("processed" if rows or not rejects else "rejected") / f.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(f), dest)
        log.info("feed processed", extra=dlog.kv(feed_id=feed_id, entries=len(rows), rejected=len(rejects),
                                                  new_matches=len(alerts)))
        n += 1
    return n


def main() -> None:
    log = dlog.setup("matcher")
    feeds = Path(os.environ.get("DWTA_FEEDS_DIR", "/lab/feeds"))
    run_dir = Path(os.environ.get("DWTA_RUN_DIR", "/lab/run"))
    for d in ("inbox", "processed", "rejected"):
        (feeds / d).mkdir(parents=True, exist_ok=True)
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    with connect() as conn:
        check_schema(conn)
        log.info("matcher started")
        while not stop:
            process_inbox(conn, feeds, run_dir, log)
            with conn.transaction():
                alerts = reverse_match(conn)
            publish_alerts(run_dir, CONSUMER, alerts)
            for a in alerts:
                log.info("alert", extra=dlog.kv(kind=a["kind"], severity=a["severity"], artifact_id=a["artifact_id"]))
            time.sleep(1.0)
    log.info("matcher stopped")


if __name__ == "__main__":
    main()
