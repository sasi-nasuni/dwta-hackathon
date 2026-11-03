"""Step ⑤ of the core idea: antivirus rescan of the flagged files (spec §5.10.4).

v1 ships the interface and the ``none`` scanner (every verdict ``not_scanned``); v2 adds a ClamAV scanner and the
product would plug in the Edge antivirus. A scanner must never block the review (AV-04).
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class AvVerdict:
    verdict: str                      # detected | clean | not_scanned | error
    signature: str | None = None
    engine: str | None = None
    definitions: str | None = None
    scanned_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scanned_at"] = self.scanned_at.isoformat() if self.scanned_at else None
        return d


class AvScanner(Protocol):
    name: str

    def scan(self, volume: str, path: str) -> AvVerdict: ...


class NullScanner:
    """v1: no antivirus in the lab yet (D-37/ClamAV in v2)."""

    name = "none"

    def scan(self, volume: str, path: str) -> AvVerdict:
        return AvVerdict("not_scanned", engine=self.name)


def scanner_from_env() -> AvScanner:
    kind = os.environ.get("DWTA_AV_SCANNER", "none")
    if kind != "none":
        raise ValueError(f"AV scanner {kind!r} is not available in v1 (ClamAV arrives in v2)")
    return NullScanner()


def apply_verdict(score: int, reasons: list[dict[str, Any]], v: AvVerdict, ranking: dict[str, Any]) -> int:
    """AV-02: a detection adds S-AV with the signature as evidence. Returns the new score."""
    sig = ranking["signals"].get("S-AV", {})
    if v.verdict == "detected" and sig.get("enabled", False):
        w = int(sig.get("weight", 0))
        reasons.append({"signal": "S-AV", "weight": w,
                        "evidence": {"signature": v.signature, "engine": v.engine, "definitions": v.definitions}})
        return score + w
    return score
