"""Simulated clock (spec §5.3.4): maps real wall-clock time to story time.

The simulator appends one entry per scenario step to ``run/simclock.jsonl``::

    {"run_id": "...", "sim_now": "2026-11-02T09:14:00.000000Z", "wall_anchor": "2026-11-03T06:12:44.000000Z"}

Any reader converts a wall-clock timestamp with the latest entry whose ``wall_anchor`` is at or before it:
``sim_ts = sim_now + (wall_ts - wall_anchor)``. Without an entry, ``sim_ts = wall_ts``.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .fileio import append_jsonl, read_jsonl
from .timeutil import iso, parse_iso

_AT = re.compile(r"^D(\d+)\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$")


def parse_at(at: str, epoch: datetime) -> datetime:
    """``"D7 02:00"`` -> epoch + 6 days + 2 h. Day 1 starts at the epoch."""
    m = _AT.match(at.strip())
    if not m:
        raise ValueError(f"invalid simulated time {at!r}; expected 'D<day> HH:MM[:SS]'")
    day, hh, mm, ss = int(m[1]), int(m[2]), int(m[3]), int(m[4] or 0)
    if day < 1 or hh > 23 or mm > 59 or ss > 59:
        raise ValueError(f"invalid simulated time {at!r}")
    return epoch + timedelta(days=day - 1, hours=hh, minutes=mm, seconds=ss)


@dataclass(frozen=True)
class ClockEntry:
    run_id: str
    sim_now: datetime
    wall_anchor: datetime


def append_entry(path: Path, run_id: str, sim_now: datetime, wall_anchor: datetime) -> None:
    append_jsonl(path, {"run_id": run_id, "sim_now": iso(sim_now), "wall_anchor": iso(wall_anchor)})


class SimClockReader:
    """Reloads the clock file whenever it grows; safe to call on every event."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._size = -1
        self._anchors: list[datetime] = []
        self._entries: list[ClockEntry] = []

    def _reload(self) -> None:
        size = self.path.stat().st_size if self.path.exists() else 0
        if size == self._size:
            return
        rows = read_jsonl(self.path)
        entries = sorted(
            (ClockEntry(r["run_id"], parse_iso(r["sim_now"]), parse_iso(r["wall_anchor"])) for r in rows),
            key=lambda e: e.wall_anchor,
        )
        self._entries = entries
        self._anchors = [e.wall_anchor for e in entries]
        self._size = size

    def to_sim(self, wall: datetime) -> datetime:
        self._reload()
        i = bisect.bisect_right(self._anchors, wall) - 1
        if i < 0:
            return wall
        e = self._entries[i]
        return e.sim_now + (wall - e.wall_anchor)
