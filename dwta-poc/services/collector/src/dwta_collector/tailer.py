"""Follows ``audit.log`` across restarts and rotation (COL-07). The read position lives in ``collector.state``."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dwta_core.fileio import atomic_write_json


@dataclass
class TailState:
    inode: int = 0
    offset: int = 0


class AuditTailer:
    def __init__(self, path: Path, state_path: Path) -> None:
        self.path = path
        self.state_path = state_path
        self.state = self._load()
        self._fh = None

    def _load(self) -> TailState:
        if self.state_path.exists():
            d = json.loads(self.state_path.read_text())
            return TailState(d.get("inode", 0), d.get("offset", 0))
        return TailState()

    def save(self, safe_offset: int) -> None:
        atomic_write_json(self.state_path, {"inode": self.state.inode, "offset": safe_offset})

    def _open(self) -> bool:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        if st.st_ino != self.state.inode or st.st_size < self.state.offset:
            # rotation (new inode) or copy-truncate (file shrank): finish the old file first, then start over
            if self._fh is not None and st.st_ino != self.state.inode:
                self._fh.seek(self.state.offset)
                rest = self._fh.read()
                end = rest.rfind(b"\n")
                self._pending_old = rest[: end + 1] if end >= 0 else b""
            if self._fh:
                self._fh.close()
                self._fh = None
            self.state = TailState(st.st_ino, 0)
        if self._fh is None:
            self._fh = self.path.open("rb")
        return True

    def read_lines(self, max_bytes: int = 4 * 1024 * 1024) -> list[tuple[int, str]]:
        """Complete lines since the last call, each with its starting byte offset."""
        if not self._open():
            return []
        old = getattr(self, "_pending_old", b"")
        if old:
            self._pending_old = b""
            # offset 0: if we crash now, the new file is re-read from the start (ids keep it duplicate-free)
            return [(0, raw.decode("utf-8", errors="replace")) for raw in old.splitlines(keepends=True)]
        self._fh.seek(self.state.offset)
        chunk = self._fh.read(max_bytes)
        end = chunk.rfind(b"\n")
        if end < 0:
            return []
        out, pos = [], self.state.offset
        for raw in chunk[: end + 1].splitlines(keepends=True):
            out.append((pos, raw.decode("utf-8", errors="replace")))
            pos += len(raw)
        self.state.offset = pos
        return out

    def at_eof(self) -> bool:
        try:
            return os.path.getsize(self.path) <= self.state.offset
        except FileNotFoundError:
            return True
