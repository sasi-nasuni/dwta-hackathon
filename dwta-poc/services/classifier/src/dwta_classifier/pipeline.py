"""Per-event processing: content pass -> typing -> analyzers -> version link -> artifact row -> alerts."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from dwta_core.timeutil import parse_iso
from dwta_ledger.common import insert_alert
from psycopg.types.json import Jsonb

from .analyzers import OletoolsAnalyzer, Signal, YaraAnalyzer
from .content import ContentFacts, SinglePass
from .rules import RuleHit, evaluate, ext_mismatch, ext_of
from .typers import MagikaTyper, RulesTyper, TypeVerdict

log = logging.getLogger("classifier.pipeline")


@dataclass
class Config:
    data_dir: Path
    share_kinds: dict[str, str]
    ext_map: dict[str, list[str]]
    rules: dict[str, Any]
    magika_min_score: float
    version: str


class Pipeline:
    def __init__(self, cfg: Config, content: SinglePass, rules_typer: RulesTyper, magika: MagikaTyper | None,
                 oletools: OletoolsAnalyzer, yara: YaraAnalyzer) -> None:
        self.cfg, self.content, self.rules_typer, self.magika = cfg, content, rules_typer, magika
        self.oletools, self.yara = oletools, yara

    # ------------------------------------------------------------------ classification (no DB)
    def classify(self, volume: str, path: str) -> tuple[ContentFacts | None, TypeVerdict | None, TypeVerdict | None, list[Signal]]:
        try:
            facts = self.content.run(self.cfg.data_dir / volume / path.lstrip("/"))
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None, None, None, []
        rv = self.rules_typer.type(facts)
        av = None
        if self.magika:
            try:
                av = self.magika.type(facts)
            except Exception as e:  # CLS-06: the AI never takes down the core
                log.warning("magika failed: %s", e)
        data = facts.content if facts.content is not None else facts.head + facts.tail
        name = path.rsplit("/", 1)[-1]
        signals: list[Signal] = []
        if self.oletools.applies_to(rv.type_class, rv.label) or (av and self.oletools.applies_to(av.type_class, av.label)):
            signals += self.oletools.analyze(data, name)
        signals += self.yara.analyze(data, name)
        if any(s.id == "macro.present" for s in signals):  # macro found inside an office file
            if rv.type_class == "office_doc":
                rv = TypeVerdict("office_macro", rv.label, rv.confidence, {**rv.evidence, "macros": True})
            if av and av.type_class == "office_doc":
                av = TypeVerdict("office_macro", av.label, av.confidence, av.evidence)
        return facts, rv, av, signals

    def mode_type(self, rv: TypeVerdict | None, av: TypeVerdict | None) -> str | None:
        if av and av.confidence >= self.cfg.magika_min_score:
            return av.type_class
        return rv.type_class if rv else None

    # ------------------------------------------------------------------ ledger
    def handle(self, conn: psycopg.Connection, ev: dict[str, Any]) -> list[dict[str, Any]]:
        op = ev["op"]
        if op == "write_close":
            return self._write(conn, ev)
        if op == "rename":
            self._rename(conn, ev)
        elif op == "delete":
            conn.execute("UPDATE files SET status = 'deleted', deleted_by = %s, deleted_sim_ts = %s "
                         "WHERE volume = %s AND current_path = %s AND status = 'present'",
                         (ev.get("user"), parse_iso(ev["sim_ts"]), ev["volume"], ev["path"]))
        return []

    def _rename(self, conn: psycopg.Connection, ev: dict[str, Any]) -> None:
        vol, src, dst = ev["volume"], ev["prev_path"], ev["path"]
        conn.execute("UPDATE files SET status = 'replaced' WHERE volume = %s AND current_path = %s AND status = 'present'",
                     (vol, dst))
        conn.execute("UPDATE files SET current_path = %s WHERE volume = %s AND current_path = %s AND status = 'present'",
                     (dst, vol, src))

    def _write(self, conn: psycopg.Connection, ev: dict[str, Any]) -> list[dict[str, Any]]:
        if conn.execute("SELECT 1 FROM artifacts WHERE event_id = %s", (ev["event_id"],)).fetchone():
            return []  # already processed (replay)
        vol, path = ev["volume"], ev["path"]
        facts, rv, av, signals = self.classify(vol, path)
        status = "gone_before_read" if facts is None else (
            "changed_since_event" if ev.get("size") is not None and facts.size != ev["size"] else "ok")
        if status == "changed_since_event":
            # CLS-04: the file was overwritten before we read it. Those bytes belong to the later write, whose own
            # event will classify them; attributing them here would blame the wrong writer.
            facts, rv, av, signals = None, None, None, []
        ext = ext_of(path)
        share_kind = self.cfg.share_kinds.get(vol, "document")
        t_rules, t_ai = (rv.type_class if rv else None), self.mode_type(rv, av)

        prev = conn.execute(
            "SELECT f.file_id, f.version_count, a.artifact_id, a.sha256, a.type_rules, a.type_ai, a.ext_mismatch_ai "
            "FROM files f LEFT JOIN artifacts a ON a.artifact_id = f.latest_artifact_id "
            "WHERE f.volume = %s AND f.current_path = %s AND f.status = 'present' FOR UPDATE OF f", (vol, path)).fetchone()
        sim_ts = parse_iso(ev["sim_ts"])
        if prev:
            file_id, version_no, change = prev["file_id"], prev["version_count"] + 1, "overwrite"
        else:
            file_id = conn.execute(
                "INSERT INTO files (volume, current_path, first_seen_sim_ts, status) VALUES (%s,%s,%s,'present') "
                "RETURNING file_id", (vol, path, sim_ts)).fetchone()["file_id"]
            version_no, change = 1, "new_file"
        sha = facts.sha256 if facts else None
        same = bool(prev and sha and prev["sha256"] == sha)
        mm_rules = ext_mismatch(ext, t_rules, self.cfg.ext_map)
        mm_ai = ext_mismatch(ext, t_ai, self.cfg.ext_map)
        art = conn.execute(
            "INSERT INTO artifacts (event_id, file_id, version_no, change_kind, prev_artifact_id, prev_sha256, prev_type_rules,"
            " prev_type_ai, same_content, volume, share_kind, path, ext, content_status, size, sha256, type_rules, type_ai,"
            " ai_label, ai_score, ext_mismatch_rules, ext_mismatch_ai, signals, analysis, \"user\", client_ip, client_name,"
            " client_origin, source, ts, sim_ts, classifier_version) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING artifact_id",
            (ev["event_id"], file_id, version_no, change, prev["artifact_id"] if prev else None,
             prev["sha256"] if prev else None, prev["type_rules"] if prev else None, prev["type_ai"] if prev else None,
             same, vol, share_kind, path, ext, status, facts.size if facts else ev.get("size"), sha, t_rules,
             av.type_class if av else None, av.label if av else None, av.confidence if av else None, mm_rules, mm_ai,
             Jsonb([s.to_dict() for s in signals]), facts.analysis if facts else "none", ev.get("user"),
             ev.get("client_ip"), ev.get("client_name"), ev.get("client_origin"), ev["source"], parse_iso(ev["ts"]),
             sim_ts, self.cfg.version)).fetchone()["artifact_id"]
        conn.execute("UPDATE files SET latest_artifact_id = %s, version_count = %s WHERE file_id = %s",
                     (art, version_no, file_id))

        common = dict(ext=ext, share_kind=share_kind, signals=signals, same_content=same, cfg=self.cfg.rules)
        hits_rules = evaluate(type_class=t_rules, mismatch=mm_rules, prev_type=prev["type_rules"] if prev else None, **common)
        hits_ai = evaluate(type_class=t_ai, mismatch=mm_ai, prev_type=prev["type_ai"] if prev else None, **common)
        return self._alerts(conn, art, sim_ts, path, hits_rules, hits_ai)

    def _alerts(self, conn, art: int, sim_ts, path: str, hits_rules: list[RuleHit], hits_ai: list[RuleHit]) -> list[dict]:
        by_rule = {h.rule_id: h for h in hits_rules}
        by_ai = {h.rule_id: h for h in hits_ai}
        out = []
        for rid in sorted(set(by_rule) | set(by_ai)):
            hr, ha = by_rule.get(rid), by_ai.get(rid)
            modes = [("both", hr)] if hr and ha and hr.severity == ha.severity else \
                [m for m in (("rules", hr), ("rules_ai", ha)) if m[1]]
            for mode, h in modes:
                a = insert_alert(conn, kind="write_time", severity=h.severity, mode=mode, rule_ids=[h.rule_id.split(":")[0]],
                                 reasons=[{"rule": h.rule_id, "path": path, **r} for r in h.reasons], sim_ts=sim_ts,
                                 artifact_id=art)
                if a:
                    out.append(a)
        return out
