"""Fallback / cross-check source: inotify on the share data (COL-20, COL-21). Sees final state, not who."""

from __future__ import annotations

import queue
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dwta_core.timeutil import utcnow
from watchdog.events import FileClosedEvent, FileDeletedEvent, FileMovedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .correlator import is_ignored, is_temp


@dataclass(frozen=True)
class WatchEvent:
    op: str
    ts: datetime
    volume: str
    path: str
    prev_path: str | None
    via_rename: bool


class _Handler(FileSystemEventHandler):
    def __init__(self, root: Path, out: queue.Queue[WatchEvent]) -> None:
        self.root = root
        self.out = out

    def _split(self, p: str) -> tuple[str, str] | None:
        rel = Path(p).relative_to(self.root).as_posix()
        if "/" not in rel:
            return None
        volume, rest = rel.split("/", 1)
        return volume, "/" + rest

    def _put(self, op: str, path: str, prev: str | None = None, via_rename: bool = False) -> None:
        if not is_ignored(path):
            v_p = self._split(path)
            if v_p:
                prev_rel = self._split(prev)[1] if prev else None
                self.out.put(WatchEvent(op, utcnow(), v_p[0], v_p[1], prev_rel, via_rename))

    def on_closed(self, event: FileClosedEvent) -> None:  # IN_CLOSE_WRITE
        if not event.is_directory and not is_temp(event.src_path):
            self._put("write_close", event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        if is_temp(event.src_path) and not is_temp(event.dest_path):
            self._put("write_close", event.dest_path, event.src_path, True)
        elif not is_temp(event.dest_path):
            self._put("rename", event.dest_path, event.src_path)

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if not event.is_directory and not is_temp(event.src_path):
            self._put("delete", event.src_path)


class Watcher:
    def __init__(self, data_dir: Path) -> None:
        self.events: queue.Queue[WatchEvent] = queue.Queue()
        self._observer = Observer()
        self._observer.schedule(_Handler(data_dir, self.events), str(data_dir), recursive=True)

    def start(self) -> None:
        self._observer.start()

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)

    def drain(self) -> list[WatchEvent]:
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                return out
