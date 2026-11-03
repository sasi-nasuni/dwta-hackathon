"""Loads configuration files from ``specs/config`` (rules, weights and thresholds are config, not code)."""

from __future__ import annotations

import hashlib
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def specs_dir() -> Path:
    """``$DWTA_SPECS_DIR``, else the ``specs/`` folder of the source checkout."""
    env = os.environ.get("DWTA_SPECS_DIR")
    if env:
        return Path(env)
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "specs"
        if (candidate / "config").is_dir():
            return candidate
    raise FileNotFoundError("specs/ not found; set DWTA_SPECS_DIR")


@dataclass(frozen=True)
class LoadedConfig:
    name: str
    data: dict[str, Any]
    sha256: str

    @property
    def version(self) -> str:
        return str(self.data.get("version", "unversioned"))


def load_config(name: str, base: Path | None = None) -> LoadedConfig:
    """``load_config("ranking")`` reads ``specs/config/ranking.toml``; returns its content and hash."""
    path = (base or specs_dir()) / "config" / f"{name}.toml"
    raw = path.read_bytes()
    return LoadedConfig(name, tomllib.loads(raw.decode()), hashlib.sha256(raw).hexdigest())
