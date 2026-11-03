"""Turns audit records into file events (COL-03..06, COL-40).

* A handle becomes *dirty* when it is created/truncated or written; its ``close`` completes one write.
* Writes to temp names (``~WRL*.tmp`` …) are held for ``rename_window`` seconds. A rename of the held temp
  file to a real name becomes ONE ``write_close`` on the final path (``via_rename``); otherwise the temp
  write is emitted when the window expires (COL-06).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .audit import AuditRecord

TEMP_PATTERNS = ("~wrl*.tmp", "~$*", "*.tmp", ".~lock*")
IGNORE_PATTERNS = (".ds_store", "._*", "thumbs.db", "desktop.ini")
CREATE_DISPOSITIONS = {"create", "overwrite_if", "overwrite", "supersede"}
WRITE_OPS = {"pwrite", "pwrite_send", "pwrite_recv", "write"}


def _base(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


def is_temp(path: str) -> bool:
    return any(fnmatch.fnmatch(_base(path), p) for p in TEMP_PATTERNS)


def is_ignored(path: str) -> bool:
    return ":" in path or any(fnmatch.fnmatch(_base(path), p) for p in IGNORE_PATTERNS)


@dataclass(frozen=True)
class RawEvent:
    """Correlated event before enrichment (sim_ts, size, origin) and id assignment."""

    op: str
    ts: datetime
    volume: str
    path: str
    prev_path: str | None
    via_rename: bool
    rec: AuditRecord


@dataclass
class _Hold:
    rec: AuditRecord
    volume: str
    path: str
    deadline: datetime


@dataclass
class Correlator:
    share_root: str = "/srv/shares"
    rename_window: float = 5.0
    ignored: int = 0
    unparsed: int = 0
    _dirty: dict[tuple[str, str], AuditRecord] = field(default_factory=dict)  # (pid, abs path) -> first dirtying record
    _holds: dict[tuple[str, str], _Hold] = field(default_factory=dict)        # (volume, rel path) -> held temp write

    def _rel(self, share: str, abspath: str) -> str | None:
        prefix = f"{self.share_root}/{share}"
        if abspath == prefix:
            return "/"
        if abspath.startswith(prefix + "/"):
            return abspath[len(prefix):]
        return None

    def safe_offset(self, current: int) -> int:
        """Earliest audit offset still needed after a restart (open dirty handles, held temp writes)."""
        offs = [r.offset for r in self._dirty.values()] + [h.rec.offset for h in self._holds.values()]
        return min(offs + [current])

    def feed(self, rec: AuditRecord) -> list[RawEvent]:
        if not rec.ok or rec.share in ("IPC_", "IPC$") or not rec.args:
            return []
        out: list[RawEvent] = []
        op = rec.op
        if op == "create_file":
            # args: access_mask | file|dir | disposition | path
            if len(rec.args) >= 4 and rec.args[1] == "file" and rec.args[2] in CREATE_DISPOSITIONS:
                self._dirty.setdefault((rec.pid, rec.args[-1]), rec)
        elif op in WRITE_OPS:
            self._dirty.setdefault((rec.pid, rec.args[-1]), rec)
        elif op == "close":
            if self._dirty.pop((rec.pid, rec.args[-1]), None) is not None:
                out += self._completed_write(rec, rec.args[-1])
        elif op == "renameat" and len(rec.args) >= 2:
            out += self._rename(rec, rec.args[0], rec.args[1])
        elif op == "unlinkat":
            out += self._simple(rec, "delete", rec.args[-1])
        elif op == "mkdirat":
            out += self._simple(rec, "mkdir", rec.args[-1])
        return out

    def _completed_write(self, rec: AuditRecord, abspath: str) -> list[RawEvent]:
        rel = self._rel(rec.share, abspath)
        if rel is None:
            return []
        if is_ignored(rel):
            self.ignored += 1
            return []
        if is_temp(rel):
            self._holds[(rec.share, rel)] = _Hold(rec, rec.share, rel, rec.ts + timedelta(seconds=self.rename_window))
            return []
        return [RawEvent("write_close", rec.ts, rec.share, rel, None, False, rec)]

    def _rename(self, rec: AuditRecord, src_abs: str, dst_abs: str) -> list[RawEvent]:
        src, dst = self._rel(rec.share, src_abs), self._rel(rec.share, dst_abs)
        if src is None or dst is None:
            return []
        # a dirty handle moves with the file
        for key in [k for k in self._dirty if k[1] == src_abs]:
            self._dirty[(key[0], dst_abs)] = self._dirty.pop(key)
        hold = self._holds.pop((rec.share, src), None)
        if hold is not None and not is_temp(dst):
            if is_ignored(dst):
                self.ignored += 1
                return []
            return [RawEvent("write_close", rec.ts, rec.share, dst, src, True, rec)]
        if hold is not None:  # temp -> temp: keep holding under the new name
            hold.path = dst
            self._holds[(rec.share, dst)] = hold
            return []
        if is_ignored(src) and is_ignored(dst):
            self.ignored += 1
            return []
        return [RawEvent("rename", rec.ts, rec.share, dst, src, False, rec)]

    def _simple(self, rec: AuditRecord, op: str, abspath: str) -> list[RawEvent]:
        rel = self._rel(rec.share, abspath)
        if rel is None:
            return []
        if op == "delete" and self._holds.pop((rec.share, rel), None) is not None:
            return []  # a held temp file was deleted: nothing to report
        if is_ignored(rel):
            self.ignored += 1
            return []
        return [RawEvent(op, rec.ts, rec.share, rel, None, False, rec)]

    def expire(self, now: datetime) -> list[RawEvent]:
        """Emit held temp writes whose rename window has passed (call with the latest audit time)."""
        out = []
        for key, h in list(self._holds.items()):
            if h.deadline <= now:
                del self._holds[key]
                out.append(RawEvent("write_close", h.rec.ts, h.volume, h.path, None, False, h.rec))
        return out

    def drop_stale(self, now: datetime, max_age: timedelta = timedelta(minutes=10)) -> None:
        for key, r in list(self._dirty.items()):
            if now - r.ts > max_age:
                del self._dirty[key]
