"""Pre-restore review engine (B10, spec §5.10): window -> attack-outputs group -> ranking -> review list.

Reads only the ledger (RB-R3). Ranking settings are re-read for every review (ENG-07).
"""

from __future__ import annotations

import fnmatch
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from dwta_core.config import load_config
from dwta_core.fileio import atomic_write_json
from dwta_core.timeutil import iso, utcnow
from dwta_ledger.common import get_offset, insert_alert
from psycopg.types.json import Jsonb

from .av import AvScanner, AvVerdict, NullScanner, apply_verdict

log = logging.getLogger("incident.engine")
MODES = ("rules", "rules_ai")
BARRIER_LAG = timedelta(seconds=7)   # collector latency + rename window
BARRIER_TIMEOUT = 30.0


@dataclass
class Item:
    item_key: str
    item_kind: str
    score: int
    level: str
    sim_ts: datetime
    artifact_id: int | None = None
    change_kind: str | None = None
    group_members: list[int] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    view: dict[str, Any] = field(default_factory=dict)
    av: AvVerdict | None = None


def level_for(score: int, levels: dict[str, int]) -> str | None:
    for name in ("high", "medium", "low"):
        if score >= levels[name]:
            return name
    return None


def _mode_type(a: dict[str, Any], mode: str, min_ai: float) -> tuple[str | None, bool | None, str | None]:
    """(type_class, ext_mismatch, prev_type) as seen by a mode."""
    if mode == "rules_ai" and a["type_ai"] and (a["ai_score"] or 0) >= min_ai:
        return a["type_ai"], a["ext_mismatch_ai"], a["prev_type_ai"] or a["prev_type_rules"]
    return a["type_rules"], a["ext_mismatch_rules"], a["prev_type_rules"]


def score_artifact(a: dict[str, Any], inc: dict[str, Any], mode: str, ranking: dict[str, Any],
                   exec_classes: set[str], min_ai: float, feed_match_ids: list[int]) -> tuple[int, list[dict[str, Any]]]:
    sig = ranking["signals"]
    reasons: list[dict[str, Any]] = []
    ev = {"artifacts": [a["artifact_id"]]}

    def add(sid: str, weight: int, evidence: dict[str, Any]) -> None:
        if sig.get(sid, {}).get("enabled", False) and weight:
            reasons.append({"signal": sid, "weight": weight, "evidence": evidence})

    w = lambda sid: int(sig.get(sid, {}).get("weight", 0)) if isinstance(sig.get(sid, {}).get("weight"), int) else 0  # noqa: E731
    t, mismatch, prev_t = _mode_type(a, mode, min_ai)
    if feed_match_ids:
        add("S-FEED", w("S-FEED"), {"feed_matches": feed_match_ids})
    if inc["user"] and a["user"] == inc["user"]:
        add("S-USER", w("S-USER"), ev)
    if inc["client_ip"] and a["client_ip"] and str(a["client_ip"]) == str(inc["client_ip"]):
        add("S-IP", w("S-IP"), ev)
    if inc["client_name"] and a["client_name"] and a["client_name"].upper() == inc["client_name"].upper():
        add("S-HOST", w("S-HOST"), ev)
    if t in exec_classes and a["share_kind"] == "document":
        add("S-EXEC-DOC", w("S-EXEC-DOC"), {**ev, "type_class": t})
    if mismatch:
        add("S-EXT", w("S-EXT"), {**ev, "ext": a["ext"], "type_class": t})
    signals = a["signals"] or []
    if any(s["id"] == "macro.autoexec" for s in signals):
        add("S-MACRO", w("S-MACRO"), ev)
    for s in signals:
        if s["id"].startswith("yara."):
            add("S-YARA", int(s.get("weight") or 10), {**ev, "rule": s["id"][5:]})
    if t in exec_classes and prev_t and prev_t not in exec_classes and a["prev_artifact_id"]:
        add("S-TYPE-CHANGE", w("S-TYPE-CHANGE"), {"artifacts": [a["prev_artifact_id"], a["artifact_id"]],
                                                  "from": prev_t, "to": t})
    return sum(r["weight"] for r in reasons), reasons


def is_attack_output(c: dict[str, Any], deleted: dict[str, tuple[str | None, datetime | None]],
                     cfg: dict[str, Any]) -> bool:
    """Spec §5.10.2. ``deleted`` maps a deleted path to (deleted_by, deleted_sim_ts)."""
    path = c["current_path"]
    name = path.rsplit("/", 1)[-1]
    low = name.lower()
    if any(low.endswith(ext) for ext in cfg["extensions"]):
        return True
    if any(fnmatch.fnmatch(low, p.lower()) for p in cfg["note_names"]):
        return True
    ro = cfg.get("replaced_original", {})
    if ro.get("enabled") and "." in name:
        orig = deleted.get(path.rsplit(".", 1)[0])
        if orig is None:
            return False
        by, when = orig
        same_user = by is not None and by == c["user"]
        close = when is not None and abs((c["sim_ts"] - when).total_seconds()) <= float(ro.get("within_seconds", 60))
        return same_user and close
    return False


def sort_items(items: list[Any], tie_break: list[str]) -> list[Any]:
    """Orders review items by ``ranking.toml`` → ``tie_break`` (e.g. ["score:desc", "sim_ts:asc"])."""
    fields = {"score": lambda i: i.score, "sim_ts": lambda i: i.sim_ts, "path": lambda i: i.view.get("path") or ""}
    out = sorted(items, key=lambda i: i.item_key)  # deterministic final tie-break (ENG-04)
    for spec in reversed(tie_break):
        field, _, direction = spec.partition(":")
        if field not in fields:
            raise ValueError(f"ranking.toml tie_break: unknown field {field!r}; use {sorted(fields)}")
        out.sort(key=fields[field], reverse=direction == "desc")
    return out


class Engine:
    def __init__(self, conn: psycopg.Connection, run_dir: Path, scanner: AvScanner | None = None) -> None:
        self.conn = conn
        self.run_dir = run_dir
        self.scanner = scanner or NullScanner()

    def wait_barrier(self, created_at: datetime) -> bool:
        """True if the classifier has caught up with everything written before the incident (spec §5.10.1)."""
        deadline = time.monotonic() + BARRIER_TIMEOUT
        while True:
            hw = get_offset(self.conn, "classifier")["high_water_ts"]
            if hw and hw >= created_at + BARRIER_LAG:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)

    def review(self, incident_id: str, wait: bool = True) -> dict[str, Any]:
        conn = self.conn
        inc = conn.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if inc is None:
            raise KeyError(f"unknown incident {incident_id}")
        if inc["state"] == "finalized":
            raise PermissionError(f"incident {incident_id} is finalized; its review can no longer change")
        if inc["restore_time_sim_ts"] is None:
            raise ValueError(f"incident {incident_id} has no restore time yet")
        complete = self.wait_barrier(inc["created_at"]) if wait else True
        ranking = load_config("ranking")
        outputs_cfg = load_config("attack_outputs")
        rules_cfg = load_config("rules").data
        min_ai = float(load_config("magika_map").data.get("min_score", 0.8))
        exec_classes = set(rules_cfg["executable_classes"])
        rk = ranking.data
        lo, hi = inc["restore_time_sim_ts"], inc["detected_sim_ts"]

        with conn.transaction():
            cands = conn.execute(
                "SELECT a.*, f.current_path, f.file_id AS fid FROM files f JOIN artifacts a ON a.artifact_id = f.latest_artifact_id "
                "WHERE f.status = 'present' AND a.volume = ANY(%s) AND a.sim_ts >= %s AND a.sim_ts <= %s "
                "ORDER BY a.sim_ts, a.artifact_id", (inc["volumes"], lo, hi)).fetchall()
            gone = conn.execute(
                "SELECT count(DISTINCT f.file_id) AS n FROM files f JOIN artifacts a ON a.file_id = f.file_id "
                "WHERE f.status <> 'present' AND a.volume = ANY(%s) AND a.sim_ts >= %s AND a.sim_ts <= %s",
                (inc["volumes"], lo, hi)).fetchone()["n"]
            deleted = {r["current_path"]: (r["deleted_by"], r["deleted_sim_ts"]) for r in conn.execute(
                "SELECT current_path, deleted_by, deleted_sim_ts FROM files WHERE status = 'deleted' AND volume = ANY(%s)",
                (inc["volumes"],))}
            fm: dict[int, list[int]] = {}
            for r in conn.execute("SELECT match_id, artifact_id FROM feed_matches WHERE artifact_id = ANY(%s) ORDER BY match_id",
                                  ([c["artifact_id"] for c in cands],)):
                fm.setdefault(r["artifact_id"], []).append(r["match_id"])

            group = [c for c in cands if is_attack_output(c, deleted, outputs_cfg.data)]
            verdicts: dict[int, AvVerdict] = {}
            group_ids = {c["artifact_id"] for c in group}
            result: dict[str, list[Item]] = {}
            for mode in MODES:
                items: list[Item] = []
                for a in cands:
                    if a["artifact_id"] in group_ids:
                        continue
                    score, reasons = score_artifact(a, inc, mode, rk, exec_classes, min_ai, fm.get(a["artifact_id"], []))
                    if score < rk["min_score"]:
                        continue
                    # step ⑤: rescan only flagged files, once per review (AV-01, AV-05); never blocks (AV-04)
                    if a["artifact_id"] not in verdicts:
                        try:
                            verdicts[a["artifact_id"]] = self.scanner.scan(a["volume"], a["current_path"])
                        except Exception as e:
                            verdicts[a["artifact_id"]] = AvVerdict("error", engine=self.scanner.name, signature=str(e)[:200])
                    score = apply_verdict(score, reasons, verdicts[a["artifact_id"]], rk)
                    t, _, _ = _mode_type(a, mode, min_ai)
                    items.append(Item(f"artifact:{a['artifact_id']}", "file", score, level_for(score, rk["levels"]),
                                      a["sim_ts"], a["artifact_id"], a["change_kind"], reasons=reasons, view={
                                          "volume": a["volume"], "path": a["current_path"], "sha256": a["sha256"],
                                          "type_class": t, "version_no": a["version_no"], "file_id": a["fid"],
                                          "written_by": a["user"], "written_from": str(a["client_ip"]) if a["client_ip"] else None,
                                          "written_at": iso(a["sim_ts"])}, av=verdicts[a["artifact_id"]]))
                if group:
                    writers = sorted({g["user"] or "?" for g in group})
                    items.append(Item("group:attack_outputs", "attack_outputs_group", rk["levels"]["high"], "high",
                                      min(g["sim_ts"] for g in group), artifact_id=None, change_kind="new_file",
                                      group_members=[g["artifact_id"] for g in group],
                                      reasons=[{"signal": "ATTACK-OUTPUTS", "weight": rk["levels"]["high"],
                                                "evidence": {"artifacts": [g["artifact_id"] for g in group]}}],
                                      view={"count": len(group), "samples": sorted(g["current_path"] for g in group)[:5],
                                       "writers": writers, "from": iso(min(g["sim_ts"] for g in group)),
                                       "to": iso(max(g["sim_ts"] for g in group))}))
                result[mode] = sort_items(items, rk.get("tie_break", ["score:desc", "sim_ts:asc"]))

            conn.execute("DELETE FROM review_items WHERE incident_id = %s", (incident_id,))
            for mode, items in result.items():
                for rank, it in enumerate(items, 1):
                    conn.execute(
                        "INSERT INTO review_items (incident_id, mode, item_key, rank, item_kind, artifact_id, group_members,"
                        " change_kind, score, suspicion_level, reasons, av_verdict, av_signature, av_engine, av_definitions,"
                        " av_scanned_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (incident_id, mode, it.item_key, rank, it.item_kind, it.artifact_id, it.group_members or None,
                         it.change_kind, it.score, it.level, Jsonb(it.reasons), it.av.verdict if it.av else None,
                         it.av.signature if it.av else None, it.av.engine if it.av else None,
                         it.av.definitions if it.av else None, it.av.scanned_at if it.av else None))
            listed = {it.item_key for items in result.values() for it in items}
            conn.execute("DELETE FROM review_decisions WHERE incident_id = %s AND NOT (item_key = ANY(%s))",
                         (incident_id, list(listed)))
            conn.execute("UPDATE incidents SET state = 'under_review', config_version = %s, config_sha256 = %s, "
                         "incomplete = %s WHERE incident_id = %s",
                         (ranking.version, f"{ranking.sha256}:{outputs_cfg.sha256}", not complete, incident_id))
            top = result["rules"][:3]
            alert = insert_alert(conn, kind="incident", severity="critical", mode="both", rule_ids=["PRE-RESTORE-REVIEW"],
                                 reasons=[{"listed": {m: len(v) for m, v in result.items()},
                                           "top": [i.view.get("path") or i.item_key for i in top]}],
                                 sim_ts=inc["detected_sim_ts"], incident_id=incident_id)
        doc = self._review_doc(inc, result, ranking, outputs_cfg, not complete, gone)
        atomic_write_json(self.run_dir / "incidents" / incident_id / "review-list.json", doc)
        return {"doc": doc, "alert": alert}

    def _review_doc(self, inc, result, ranking, outputs_cfg, incomplete: bool, gone: int) -> dict[str, Any]:
        decisions = {r["item_key"]: r for r in self.conn.execute(
            "SELECT * FROM review_decisions WHERE incident_id = %s", (inc["incident_id"],))}

        def item(rank: int, it: Item) -> dict[str, Any]:
            d = decisions.get(it.item_key)
            out = {"rank": rank, "item_key": it.item_key, "item_kind": it.item_kind, "artifact_id": it.artifact_id,
                   **it.view, "change_kind": it.change_kind, "score": it.score, "suspicion_level": it.level,
                   "decision": d["decision"] if d else "pending", "reasons": it.reasons}
            if it.av:
                out["av"] = it.av.to_dict()
            return out

        return {"schema": "dwta.review_list/v1", "incident_id": inc["incident_id"],
                "window": {"from": iso(inc["restore_time_sim_ts"]), "to": iso(inc["detected_sim_ts"])},
                "incident": {"user": inc["user"], "client_ip": str(inc["client_ip"]) if inc["client_ip"] else None,
                             "client_name": inc["client_name"], "volumes": inc["volumes"]},
                "config": {"version": ranking.version, "ranking_sha256": ranking.sha256,
                           "attack_outputs_sha256": outputs_cfg.sha256},
                "incomplete": incomplete, "seen_but_gone": gone,
                "modes": {m: [item(r, it) for r, it in enumerate(items, 1)] for m, items in result.items()}}

    # ------------------------------------------------------------------ decisions (spec §5.10.4)
    def _check_open(self, incident_id: str) -> dict[str, Any]:
        inc = self.conn.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()
        if inc is None:
            raise KeyError(f"unknown incident {incident_id}")
        if inc["state"] == "finalized":
            raise PermissionError(f"incident {incident_id} is finalized; decisions are locked")
        if inc["state"] != "under_review":
            raise ValueError(f"incident {incident_id} is {inc['state']}; nothing to decide yet")
        return inc

    def resolve_item(self, incident_id: str, ref: str, mode: str) -> str:
        if ref.isdigit():
            row = self.conn.execute("SELECT item_key FROM review_items WHERE incident_id = %s AND mode = %s AND rank = %s",
                                    (incident_id, mode, int(ref))).fetchone()
        else:
            row = self.conn.execute("SELECT item_key FROM review_items WHERE incident_id = %s AND item_key = %s LIMIT 1",
                                    (incident_id, ref)).fetchone()
        if row is None:
            raise KeyError(f"item {ref!r} is not on the review list of {incident_id} ({mode})")
        return row["item_key"]

    def decide(self, incident_id: str, ref: str, decision: str, by: str, mode: str = "rules") -> str:
        if decision not in ("remove", "keep"):
            raise ValueError("decision must be remove or keep")
        with self.conn.transaction():
            self._check_open(incident_id)
            key = self.resolve_item(incident_id, ref, mode)
            self.conn.execute(
                "INSERT INTO review_decisions (incident_id, item_key, decision, decided_by) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (incident_id, item_key) DO UPDATE SET decision = EXCLUDED.decision, "
                "decided_by = EXCLUDED.decided_by, decided_at = now()", (incident_id, key, decision, by))
        return key

    def finalize(self, incident_id: str, by: str, mode: str = "rules") -> dict[str, Any]:
        """Locks decisions and writes the restore-exclusion manifest (spec §6.7). Refused while items are pending."""
        conn = self.conn
        with conn.transaction():
            inc = self._check_open(incident_id)
            rows = conn.execute(
                "SELECT i.*, d.decision, d.decided_by, d.decided_at, a.volume, a.path, a.sha256, a.file_id, f.current_path "
                "FROM review_items i LEFT JOIN review_decisions d ON d.incident_id = i.incident_id AND d.item_key = i.item_key "
                "LEFT JOIN artifacts a ON a.artifact_id = i.artifact_id LEFT JOIN files f ON f.file_id = a.file_id "
                "WHERE i.incident_id = %s AND i.mode = %s ORDER BY i.rank", (incident_id, mode)).fetchall()
            pending = [r["rank"] for r in rows if r["decision"] is None]
            if pending:
                raise ValueError(f"cannot finalize: {len(pending)} item(s) still pending (ranks {pending})")
            conn.execute("UPDATE incidents SET state = 'finalized', finalized_by = %s, finalized_at = now() "
                         "WHERE incident_id = %s", (by, incident_id))
            fin = conn.execute("SELECT finalized_at FROM incidents WHERE incident_id = %s", (incident_id,)).fetchone()

        def entry(r: dict[str, Any]) -> dict[str, Any]:
            e = {"item_key": r["item_key"], "item_kind": r["item_kind"], "suspicion_level": r["suspicion_level"],
                 "score": r["score"], "signals": [x["signal"] for x in r["reasons"]], "decided_by": r["decided_by"],
                 "decided_at": iso(r["decided_at"]), "action": "quarantine" if r["decision"] == "remove" else "none"}
            if r["item_kind"] == "file":
                e.update(volume=r["volume"], path=r["current_path"], file_id=r["file_id"], artifact_id=r["artifact_id"],
                         sha256=r["sha256"], change_kind=r["change_kind"],
                         av={"verdict": r["av_verdict"], "signature": r["av_signature"], "engine": r["av_engine"]})
            else:
                members = conn.execute("SELECT a.artifact_id, a.volume, f.current_path FROM artifacts a JOIN files f "
                                       "ON f.file_id = a.file_id WHERE a.artifact_id = ANY(%s) ORDER BY f.current_path",
                                       (r["group_members"],)).fetchall()
                e.update(members=[{"artifact_id": m["artifact_id"], "volume": m["volume"], "path": m["current_path"]}
                                  for m in members])
            return e

        manifest = {"schema": "dwta.restore_exclusions/v1", "incident_id": incident_id,
                    "restore_time": iso(inc["restore_time_sim_ts"]), "finalized_by": by,
                    "finalized_at": iso(fin["finalized_at"]), "mode": mode,
                    "remove": [entry(r) for r in rows if r["decision"] == "remove"],
                    "kept": [entry(r) for r in rows if r["decision"] == "keep"]}
        manifest["summary"] = {"listed": len(rows), "remove": len(manifest["remove"]), "keep": len(manifest["kept"])}
        atomic_write_json(self.run_dir / "incidents" / incident_id / "restore-exclusions.json", manifest)
        return manifest


def now_iso() -> str:
    return iso(utcnow())
