"""Scenario files (TOML, D-01): load, expand and validate before any SMB operation (SIM-03)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dwta_core.simclock import parse_at
from dwta_core.timeutil import parse_iso

from . import artifacts

RESERVED = {"at", "id", "actor", "as", "action"}


@dataclass
class Step:
    index: int
    at: str
    sim_time: datetime
    action: str
    actor: str | None
    identity: str | None
    id: str | None
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    name: str
    description: str
    epoch: datetime
    corpus: str
    steps: list[Step]
    path: Path | None = None
    randomize_names: bool = False  # new realistic file names for the corpus on every run (same bytes and folders)


class ScenarioError(ValueError):
    pass


def load(path: Path, default_epoch: str = "2026-11-02T00:00:00Z") -> Scenario:
    data = tomllib.loads(path.read_text())
    return from_dict(data, default_epoch, path)


def from_dict(data: dict[str, Any], default_epoch: str = "2026-11-02T00:00:00Z", path: Path | None = None) -> Scenario:
    epoch = parse_iso(data.get("sim_epoch", default_epoch))
    steps: list[Step] = []
    for raw in data.get("step", []):
        ats = raw.get("at")
        for at in ats if isinstance(ats, list) else [ats]:
            if not at:
                raise ScenarioError(f"step {len(steps) + 1}: missing 'at'")
            try:
                sim_time = parse_at(at, epoch)
            except ValueError as e:
                raise ScenarioError(f"step {len(steps) + 1}: {e}") from None
            params = {k: v for k, v in raw.items() if k not in RESERVED}
            steps.append(Step(len(steps) + 1, at, sim_time, raw.get("action", ""), raw.get("actor"), raw.get("as"),
                              raw.get("id"), params))
    return Scenario(data.get("name", path.stem if path else "adhoc"), data.get("description", ""), epoch,
                    data.get("corpus", "default-42"), steps, path, bool(data.get("randomize_names", False)))


def validate(sc: Scenario, lab: dict[str, Any], registry: dict[str, Any]) -> None:
    actors = lab["actors"]
    ids = set()
    prev = None
    for s in sc.steps:
        where = f"step {s.index} ({s.at}, {s.action or '?'})"
        if s.action not in registry:
            raise ScenarioError(f"{where}: unknown action; known: {sorted(registry)}")
        if prev and s.sim_time < prev:
            raise ScenarioError(f"{where}: time goes backwards")
        prev = s.sim_time
        spec = registry[s.action]
        if spec.needs_actor:
            if s.actor not in actors:
                raise ScenarioError(f"{where}: unknown actor {s.actor!r}; known: {sorted(actors)}")
            s.identity = s.identity or actors[s.actor]["identity"]
            if s.identity not in actors[s.actor]["credentials"]:
                raise ScenarioError(f"{where}: {s.actor} has no credentials for {s.identity!r}")
        share = s.params.get("share")
        if share is not None and share not in lab["shares"]:
            raise ScenarioError(f"{where}: unknown share {share!r}")
        for name in [s.params.get("artifact"), *s.params.get("include_artifacts", [])]:
            if name:
                try:
                    artifacts.get(name)
                except KeyError as e:
                    raise ScenarioError(f"{where}: {e}") from None
        if s.id:
            if s.id in ids:
                raise ScenarioError(f"{where}: duplicate step id {s.id!r}")
            ids.add(s.id)
        ref = s.params.get("from_step")
        if ref and ref not in ids:
            raise ScenarioError(f"{where}: from_step {ref!r} must name an earlier step id")
        spec.validate(s)
