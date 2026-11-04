"""Everything an action needs while a run executes: lab, clock, corpus, SMB sessions, ground truth."""

from __future__ import annotations

import random
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from dwta_core.config import load_config
from dwta_core.fileio import append_jsonl
from dwta_core.timeutil import iso, parse_iso, utcnow

from . import corpus
from .lab import Instance, repo_root
from .scenario import Scenario, Step
from .smb import SmbSession


def measure_skew(inst: Instance) -> timedelta:
    """Container clock minus host clock, so clock anchors match audit timestamps (written by Samba)."""
    container = inst.compose("ps", "-q", "samba", capture=True).stdout.decode().strip()
    best = None
    for _ in range(3):
        t0 = utcnow()
        out = subprocess.run(["docker", "exec", container, "date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"],
                             capture_output=True, text=True, check=True).stdout.strip()
        t1 = utcnow()
        remote = parse_iso(out[:26] + "Z")
        skew = remote - (t0 + (t1 - t0) / 2)
        if best is None or (t1 - t0) < best[0]:
            best = (t1 - t0, skew)
    return best[1]


@dataclass
class RunContext:
    instance: Instance
    scenario: Scenario
    run_id: str
    seed: int
    lab: dict[str, Any] = field(default_factory=lambda: load_config("lab").data)
    skew: timedelta = timedelta(0)
    steps_done: dict[str, Step] = field(default_factory=dict)
    step_facts: dict[str, dict[str, Any]] = field(default_factory=dict)  # facts an action leaves for later steps
    _sessions: dict[tuple[str, str], SmbSession] = field(default_factory=dict)
    _anchor: tuple[datetime, datetime] | None = None
    _op_seq: int = 0

    def __post_init__(self) -> None:
        self.rng = random.Random(f"{self.scenario.name}:{self.seed}")
        self.env = self.instance.env()
        self.run_dir = self.instance.run / "runs" / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.staging_host = self.instance.staging / self.run_id
        self.staging_host.mkdir(parents=True, exist_ok=True)
        # Local paths handed to actions are host paths; each transport maps them to its client (SMBC-03/04).
        self.staging_container = str(self.staging_host)
        self.pack = repo_root() / "lab" / "corpus" / self.scenario.corpus
        self.key = bytes.fromhex(self.env["SIM_KEY"])

    # ------------------------------------------------------------------ corpus
    @property
    def manifest(self) -> dict[str, Any]:
        if not hasattr(self, "_manifest"):
            if not (self.pack / "manifest.json").exists():
                raise FileNotFoundError(f"corpus pack {self.scenario.corpus} missing; run "
                                        f"`dwta-sim corpus build` first ({self.pack})")
            self._manifest = corpus.load_manifest(self.pack)
        return self._manifest

    def seeded(self, share: str) -> list[dict[str, Any]]:
        """Corpus files as they appear on the share. ``path`` is the share path, ``src`` the pack path."""
        if not hasattr(self, "_seeded"):
            files = [{**f, "src": f["path"]} for f in self.manifest["files"]]
            if self.scenario.randomize_names:
                files = corpus.randomize_names(files, random.Random(f"names:{self.run_id}"))
            self._seeded = files
        return [f for f in self._seeded if f["share"] == share]

    def corpus_container_path(self, share: str, path: str) -> str:
        return str(self.pack / "files" / share.lstrip("/") / path.lstrip("/"))

    # ------------------------------------------------------------------ clock
    def set_clock(self, sim_time: datetime) -> None:
        wall = utcnow() + self.skew
        self.instance.append_clock(self.run_id, sim_time, wall)
        self._anchor = (sim_time, wall)

    def sim_now(self) -> datetime:
        sim, wall = self._anchor
        return sim + (utcnow() + self.skew - wall)

    # ------------------------------------------------------------------ SMB + staging
    def session(self, step: Step) -> SmbSession:
        actor = self.lab["actors"][step.actor]
        key = (step.actor, step.identity)
        if key not in self._sessions:
            self._sessions[key] = SmbSession(self.instance, step.actor, step.identity, actor["netbios"])
        return self._sessions[key]

    def stage(self, name: str, data: bytes) -> str:
        """Writes bytes to the staging folder; returns the host path (the transport maps it to the client)."""
        p = self.staging_host / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)

    def staged_bytes(self, name: str) -> bytes:
        return (self.staging_host / name).read_bytes()

    # ------------------------------------------------------------------ ground truth (SIM-05)
    def truth(self, step: Step, *, op: str, share: str | None, path: str | None, expected_event: str | None,
              prev_path: str | None = None, artifact: str | None = None, sha256: str | None = None,
              result: str = "ok", **extra: Any) -> None:
        self._op_seq += 1
        actor = self.lab["actors"].get(step.actor or "", {})
        append_jsonl(self.run_dir / "groundtruth.jsonl", {
            "schema": "dwta.groundtruth/v1", "run_id": self.run_id, "scenario": self.scenario.name,
            "step": step.index, "op_id": f"{self.run_id}/{self._op_seq:05d}", "sim_ts": iso(self.sim_now()),
            "wall_ts": iso(utcnow() + self.skew), "actor": step.actor, "identity": step.identity,
            "client_ip": self.env.get(f"IP_{(step.actor or '').upper().replace('-', '_')}") if step.actor else None,
            "client_name": actor.get("netbios"), "action": step.action, "volume": share, "op": op, "path": path,
            "prev_path": prev_path, "artifact": artifact, "sha256": sha256, "malicious": actor.get("role") == "attacker",
            "result": result, "expected_event": expected_event, **extra,
        })

    def settle(self, seconds: float = 0.3) -> None:
        time.sleep(seconds)
