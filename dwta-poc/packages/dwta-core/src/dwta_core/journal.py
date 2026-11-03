"""Event journal (spec §5.4.6, COL-50..52): append-only JSONL segments, gzipped when closed.

Layout::

    <root>/2026-11-03/06-000.jsonl      open segment (hour of the events' ``ts``)
    <root>/2026-11-03/05-000.jsonl.gz   closed segment
    <root>/INDEX                        one JSON line per closed segment

Segments are bucketed by the *event* timestamp, so replaying the same input produces the same journal.
A reader position is ``(segment, line)``: the segment stem and how many lines of it were consumed.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fileio import append_jsonl, dumps

DEFAULT_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, order=True)
class Position:
    segment: str = ""
    line: int = 0


def _stem_for(ts: str, n: int) -> str:
    # ts is canonical ISO: 2026-11-03T06:12:44.381000Z
    return f"{ts[:10]}/{ts[11:13]}-{n:03d}"


class JournalWriter:
    def __init__(
        self,
        root: Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        fsync_every_s: float = 1.0,
        fsync_every_n: int = 500,
    ) -> None:
        self.root = root
        self.max_bytes = max_bytes
        self.fsync_every_s = fsync_every_s
        self.fsync_every_n = fsync_every_n
        self._fh = None
        self._stem: str | None = None
        self._first: dict[str, Any] | None = None
        self._last: dict[str, Any] | None = None
        self._count = 0
        self._pending = 0
        self._last_sync = time.monotonic()
        root.mkdir(parents=True, exist_ok=True)
        self._resume()

    def _resume(self) -> None:
        open_segments = sorted(self.root.glob("*/*.jsonl"))
        for extra in open_segments[:-1]:  # crash left more than one open segment: close the older ones
            self._close_file(extra)
        if open_segments:
            seg = open_segments[-1]
            self._stem = f"{seg.parent.name}/{seg.stem}"
            lines = seg.read_text(encoding="utf-8").splitlines()
            self._count = len(lines)
            self._fh = seg.open("a", encoding="utf-8")

    def _path(self, stem: str) -> Path:
        return self.root / f"{stem}.jsonl"

    def _close_file(self, path: Path, first: dict | None = None, last: dict | None = None, count: int | None = None) -> None:
        gz = path.with_suffix(".jsonl.gz")
        tmp = gz.with_name(gz.name + ".tmp")
        # mtime=0 keeps the gzip bytes identical across replays (COL-52)
        with path.open("rb") as src, open(tmp, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as dst:
            shutil.copyfileobj(src, dst)
        os.replace(tmp, gz)
        path.unlink()
        stem = f"{path.parent.name}/{path.name.removesuffix('.jsonl')}"
        entry = {"segment": stem, "count": count}
        if first and last:
            entry.update(first_event_id=first["event_id"], last_event_id=last["event_id"],
                         first_sim_ts=first["sim_ts"], last_sim_ts=last["sim_ts"])
        append_jsonl(self.root / "INDEX", entry)

    def _roll(self) -> None:
        if self._fh and self._stem:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._close_file(self._path(self._stem), self._first, self._last, self._count)
        self._fh, self._stem, self._first, self._last, self._count = None, None, None, None, 0

    def append(self, event: dict[str, Any]) -> None:
        ts = event["ts"]
        bucket = _stem_for(ts, 0)[:13]
        # roll forward only: a late event from an earlier hour goes into the current segment
        if self._stem and self._fh and (bucket > self._stem[:13] or self._fh.tell() >= self.max_bytes):
            n = int(self._stem[14:]) + 1 if self._stem[:13] == bucket else 0
            self._roll()
            self._stem = _stem_for(ts, n)
        if self._stem is None:
            self._stem = _stem_for(ts, 0)
        if self._fh is None:
            p = self._path(self._stem)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("a", encoding="utf-8")
        self._fh.write(dumps(event) + "\n")
        self._first = self._first or event
        self._last = event
        self._count += 1
        self._pending += 1
        if self._pending >= self.fsync_every_n or time.monotonic() - self._last_sync >= self.fsync_every_s:
            self.sync()

    def flush(self) -> None:
        """Make appended events visible to readers now (durability still follows the fsync policy)."""
        if self._fh:
            self._fh.flush()

    def sync(self) -> None:
        if self._fh:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        self._pending = 0
        self._last_sync = time.monotonic()

    def close(self) -> None:
        self.sync()
        if self._fh:
            self._fh.close()
            self._fh = None


class JournalReader:
    def __init__(self, root: Path) -> None:
        self.root = root

    def segments(self) -> list[str]:
        stems = set()
        for p in self.root.glob("*/*.jsonl*"):
            if p.name.endswith((".jsonl", ".jsonl.gz")):
                stems.add(f"{p.parent.name}/{p.name.split('.jsonl')[0]}")
        return sorted(stems)

    def _lines(self, stem: str) -> list[str]:
        plain = self.root / f"{stem}.jsonl"
        try:
            text = plain.read_text(encoding="utf-8")
        except FileNotFoundError:
            with gzip.open(self.root / f"{stem}.jsonl.gz", "rt", encoding="utf-8") as fh:
                text = fh.read()
        lines = text.split("\n")
        return lines[:-1]  # drop the trailing partial (or empty) line

    def read(self, pos: Position | None = None, limit: int = 1000) -> Iterator[tuple[Position, dict[str, Any]]]:
        """Yields ``(position_after, event)``; resume later from the last position returned."""
        pos = pos or Position()
        emitted = 0
        for stem in self.segments():
            if pos.segment and stem < pos.segment:
                continue
            start = pos.line if stem == pos.segment else 0
            lines = self._lines(stem)
            for i in range(start, len(lines)):
                yield Position(stem, i + 1), json.loads(lines[i])
                emitted += 1
                if emitted >= limit:
                    return
