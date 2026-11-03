"""Small, safe file helpers: atomic replace and append-only JSON lines."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def dumps(obj: Any) -> str:
    """Compact, stable JSON (key order preserved, UTF-8)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    """Write via temp file + rename, so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, obj: Any, mode: int | None = None) -> None:
    atomic_write_text(path, json.dumps(obj, indent=1, ensure_ascii=False) + "\n", mode)


def append_jsonl(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(dumps(obj) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
