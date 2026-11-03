"""``dwta.fs_event/v1`` (spec §6.1): one clean file event per completed write, rename, delete or mkdir."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

SCHEMA = "dwta.fs_event/v1"
OPS = ("write_close", "rename", "delete", "mkdir")
SOURCES = ("audit", "watcher")


def event_id(source: str, ts: str, op: str, volume: str, path: str, user: str | None, pid: str | None) -> str:
    """Deterministic id (COL-08): replaying the same input yields the same id."""
    key = "|".join([source, ts, op, volume, path, user or "", pid or ""])
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class FsEvent:
    """Field order here is the serialized order (COL-52)."""

    event_id: str
    source: str
    op: str
    ts: str
    sim_ts: str
    volume: str
    path: str
    prev_path: str | None
    via_rename: bool
    user: str | None
    client_ip: str | None
    client_name: str | None
    client_origin: str | None
    size: int | None
    raw_ref: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FsEvent:
        if d.get("schema") != SCHEMA:
            raise ValueError(f"not an fs_event/v1 record: {d.get('schema')!r}")
        return cls(**{k: d[k] for k in cls.__dataclass_fields__})
