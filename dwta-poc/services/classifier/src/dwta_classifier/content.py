"""Single content pass (spec §5.11, RBQ-01/02): the ONLY place DwTA reads file content.

Files up to the hash cap are streamed once: the same bytes feed SHA-256, the head/tail windows and the
analyzers. Larger files get the head and tail windows only (FW-K1) and no hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 1024 * 1024


@dataclass
class ReadBudget:
    head_bytes: int = 65536
    tail_bytes: int = 65557
    hash_size_cap_bytes: int = 64 * 1024 * 1024

    @classmethod
    def from_config(cls, cfg: dict) -> ReadBudget:
        return cls(cfg["head_bytes"], cfg["tail_bytes"], cfg["hash_size_cap_bytes"])


@dataclass
class ContentFacts:
    size: int
    sha256: str | None
    head: bytes
    tail: bytes
    content: bytes | None          # whole file when <= cap (for analyzers in the same pass), else None
    analysis: str                  # full | partial
    bytes_read: int
    read_reasons: list[str] = field(default_factory=list)
    source: str = "dwta_single_pass"


class ReadCounter:
    """Test instrumentation (RBQ-04): bytes and reasons per path."""

    def __init__(self) -> None:
        self.reads: list[tuple[str, str, int]] = []

    def add(self, path: str, reason: str, n: int) -> None:
        self.reads.append((path, reason, n))


class SinglePass:
    name = "dwta_single_pass"

    def __init__(self, budget: ReadBudget, counter: ReadCounter | None = None) -> None:
        self.budget = budget
        self.counter = counter

    def run(self, path: Path) -> ContentFacts:
        b = self.budget
        with path.open("rb") as fh:
            size = fh.seek(0, 2)
            fh.seek(0)
            if size <= b.hash_size_cap_bytes:
                h = hashlib.sha256()
                parts = []
                while chunk := fh.read(CHUNK):
                    h.update(chunk)
                    parts.append(chunk)
                content = b"".join(parts)
                self._count(path, "pass", len(content))
                return ContentFacts(len(content), h.hexdigest(), content[: b.head_bytes], content[-b.tail_bytes:],
                                    content, "full", len(content), ["pass"])
            head = fh.read(b.head_bytes)
            fh.seek(max(size - b.tail_bytes, b.head_bytes))
            tail = fh.read(b.tail_bytes)
            self._count(path, "head", len(head))
            self._count(path, "tail", len(tail))
            return ContentFacts(size, None, head, tail, None, "partial", len(head) + len(tail), ["head", "tail"])

    def _count(self, path: Path, reason: str, n: int) -> None:
        if self.counter:
            self.counter.add(str(path), reason, n)
