"""Collector service loop (B4): audit tailer (+ watcher) -> correlated, enriched fs_events -> journal."""

from __future__ import annotations

import ipaddress
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from dwta_core import log as dlog
from dwta_core.events import FsEvent, event_id
from dwta_core.fileio import atomic_write_json, dumps
from dwta_core.journal import JournalReader, JournalWriter
from dwta_core.simclock import SimClockReader
from dwta_core.timeutil import iso, utcnow

from .audit import parse_line
from .correlator import Correlator, RawEvent
from .tailer import AuditTailer

DEDUPE_WINDOW = timedelta(seconds=3)


@dataclass
class Settings:
    audit_log: Path
    data_dir: Path
    run_dir: Path
    share_root: str
    lab_subnet: str | None
    gateway_ip: str | None
    source: str
    rename_window: float
    sink: str

    @classmethod
    def from_env(cls) -> Settings:
        e = os.environ
        source = e.get("COLLECTOR_SOURCE", "both")
        if source not in ("audit", "watcher", "both"):
            raise SystemExit(f"COLLECTOR_SOURCE must be audit|watcher|both, got {source!r}")
        return cls(Path(e.get("DWTA_AUDIT_LOG", "/lab/logs/audit.log")), Path(e.get("DWTA_DATA_DIR", "/lab/data")),
                   Path(e.get("DWTA_RUN_DIR", "/lab/run")), e.get("DWTA_SHARE_ROOT", "/srv/shares"),
                   e.get("DWTA_LAB_SUBNET"), e.get("DWTA_GATEWAY_IP"), source,
                   float(e.get("RENAME_WINDOW", "5")), e.get("COLLECTOR_SINK", "journal"))


class Collector:
    def __init__(self, s: Settings, journal: JournalWriter | None = None) -> None:
        self.s = s
        self.log = dlog.setup("collector")
        self.journal = journal or JournalWriter(s.run_dir / "journal")
        self.clock = SimClockReader(s.run_dir / "simclock.jsonl")
        self.tailer = AuditTailer(s.audit_log, s.run_dir / "collector.state")
        self.corr = Correlator(s.share_root, s.rename_window)
        self.subnet = ipaddress.ip_network(s.lab_subnet) if s.lab_subnet else None
        self.seen: set[str] = self._recent_ids()
        self.recent_audit: dict[tuple[str, str, str], datetime] = {}
        self.pending_watch: list = []
        self.metrics = {"lines": 0, "events": 0, "unparsed": 0, "duplicates_suppressed": 0,
                        "watcher_matched": 0, "watcher_emitted": 0}
        self.watcher = None
        if s.source in ("watcher", "both"):
            from .watcher import Watcher
            self.watcher = Watcher(s.data_dir)

    def _recent_ids(self) -> set[str]:
        reader = JournalReader(self.s.run_dir / "journal")
        segs = reader.segments()[-3:]
        ids: set[str] = set()
        if segs:
            from dwta_core.journal import Position
            start = Position(segs[0], 0)
            for _, ev in reader.read(start, limit=10**9):
                ids.add(ev["event_id"])
        return ids

    # ------------------------------------------------------------------ enrichment + emission
    def _origin(self, ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "host"
        return "lab" if self.subnet and addr in self.subnet and ip != self.s.gateway_ip else "host"

    def _size(self, volume: str, path: str) -> int | None:
        try:
            return (self.s.data_dir / volume / path.lstrip("/")).stat().st_size
        except (FileNotFoundError, NotADirectoryError):
            return None

    def _write(self, ev: FsEvent) -> None:
        if ev.event_id in self.seen:
            self.metrics["duplicates_suppressed"] += 1
            return
        self.seen.add(ev.event_id)
        d = ev.to_dict()
        if self.s.sink in ("journal", "both"):
            self.journal.append(d)
        if self.s.sink in ("stdout", "both"):
            sys.stdout.write(dumps(d) + "\n")
        self.metrics["events"] += 1

    def emit_audit(self, r: RawEvent) -> None:
        ts = iso(r.ts)
        sim = iso(self.clock.to_sim(r.ts))
        size = self._size(r.volume, r.path) if r.op in ("write_close", "rename") else None
        ev = FsEvent(event_id("audit", ts, r.op, r.volume, r.path, r.rec.user, r.rec.pid), "audit", r.op, ts, sim,
                     r.volume, r.path, r.prev_path, r.via_rename, r.rec.user, r.rec.client_ip, r.rec.client_name,
                     self._origin(r.rec.client_ip), size, f"audit.log@{r.rec.offset}")
        self.recent_audit[(r.volume, r.path, r.op)] = r.ts
        self._write(ev)

    def emit_watch(self, w) -> None:
        ts = iso(w.ts)
        ev = FsEvent(event_id("watcher", ts, w.op, w.volume, w.path, None, None), "watcher", w.op, ts,
                     iso(self.clock.to_sim(w.ts)), w.volume, w.path, w.prev_path, w.via_rename, None, None, None,
                     None, self._size(w.volume, w.path) if w.op != "delete" else None, None)
        self._write(ev)
        self.metrics["watcher_emitted"] += 1

    # ------------------------------------------------------------------ main steps
    def step_audit(self) -> int:
        lines = self.tailer.read_lines()
        for off, line in lines:
            self.metrics["lines"] += 1
            rec = parse_line(line, off)
            if rec is None:
                self.metrics["unparsed"] += 1
                with (self.s.run_dir / "collector-deadletter.log").open("a") as fh:
                    fh.write(line)
                continue
            for r in self.corr.feed(rec):
                self.emit_audit(r)
            for r in self.corr.expire(rec.ts):
                self.emit_audit(r)
        if self.tailer.at_eof():
            for r in self.corr.expire(utcnow()):
                self.emit_audit(r)
        self.journal.flush()
        return len(lines)

    def step_watcher(self) -> None:
        if not self.watcher:
            return
        now = utcnow()
        for w in self.watcher.drain():
            # identical inotify events in quick succession collapse into one
            if any(p.op == w.op and p.volume == w.volume and p.path == w.path for p, _ in self.pending_watch):
                continue
            self.pending_watch.append((w, now + DEDUPE_WINDOW))
        keep = []
        for w, due in self.pending_watch:
            if due > now:
                keep.append((w, due))
                continue
            if w.op == "delete" and self._size(w.volume, w.path) is not None:
                continue  # replaced by a rename onto it (office save), not deleted
            seen_at = self.recent_audit.get((w.volume, w.path, w.op))
            if self.s.source == "both" and seen_at is not None and abs(seen_at - w.ts) <= DEDUPE_WINDOW + timedelta(seconds=2):
                self.metrics["watcher_matched"] += 1
            else:
                self.emit_watch(w)
        self.pending_watch = keep
        self.journal.flush()
        cutoff = now - timedelta(minutes=2)
        self.recent_audit = {k: t for k, t in self.recent_audit.items() if t >= cutoff}

    def checkpoint(self) -> None:
        self.journal.sync()
        self.tailer.save(self.corr.safe_offset(self.tailer.state.offset))
        atomic_write_json(self.s.run_dir / "collector.metrics.json",
                          {**self.metrics, "ignored": self.corr.ignored, "updated": iso(utcnow())})

    def run(self) -> None:
        stop = False

        def _stop(*_):
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        if self.watcher:
            self.watcher.start()
        self.log.info("collector started", extra=dlog.kv(source=self.s.source, audit_log=str(self.s.audit_log)))
        last_cp = 0.0
        while not stop:
            n = self.step_audit() if self.s.source in ("audit", "both") else 0
            self.step_watcher()
            if time.monotonic() - last_cp >= 1.0:
                self.corr.drop_stale(utcnow())
                self.checkpoint()
                last_cp = time.monotonic()
            if n == 0:
                time.sleep(0.2)
        self.checkpoint()
        self.journal.close()
        if self.watcher:
            self.watcher.stop()
        self.log.info("collector stopped", extra=dlog.kv(**self.metrics))


def main() -> None:
    s = Settings.from_env()
    s.run_dir.mkdir(parents=True, exist_ok=True)
    Collector(s).run()


if __name__ == "__main__":
    main()
