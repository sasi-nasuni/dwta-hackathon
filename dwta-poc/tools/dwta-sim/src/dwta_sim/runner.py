"""Executes a scenario step by step: safety check, clock, actions, ground truth (spec §5.3)."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from dwta_core.fileio import atomic_write_json, read_jsonl
from dwta_core.timeutil import iso, utcnow

from . import keystream
from .actions import load_all
from .context import RunContext
from .lab import Instance, repo_root
from .scenario import Scenario, validate
from .smb import SmbSession as S


class SafetyError(RuntimeError):
    pass


def safety_check(inst: Instance) -> None:
    """SIM-07: refuse unless //samba resolves to this instance's Samba container on its own lab network."""
    env = inst.env()
    cid = inst.compose("ps", "-q", "samba", capture=True).stdout.decode().strip()
    if not cid:
        raise SafetyError("lab Samba container is not running")
    info = json.loads(subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=True).stdout)[0]
    nets = info["NetworkSettings"]["Networks"]
    lab_net = nets.get(f"{inst.name}-lab")
    if not lab_net or lab_net["IPAMConfig"]["IPv4Address"] != env["IP_SAMBA"]:
        raise SafetyError(f"Samba is not at {env['IP_SAMBA']} on network {inst.name}-lab; refusing to run")


def resolve_scenario(name_or_path: str) -> Path:
    p = Path(name_or_path)
    if p.exists():
        return p
    p = repo_root() / "scenarios" / f"{name_or_path}.toml"
    if not p.exists():
        raise FileNotFoundError(f"scenario {name_or_path!r} not found (looked in scenarios/)")
    return p


def run(inst: Instance, sc: Scenario, seed: int = 42, log=print, speed: str = "max") -> RunContext:
    registry = load_all()
    from dwta_core.config import load_config
    validate(sc, load_config("lab").data, registry)
    inst.safety_check()
    run_id = f"r-{utcnow():%Y%m%d-%H%M%S}"
    ctx = RunContext(inst, sc, run_id, seed)
    _ = ctx.manifest  # fail early if the corpus pack is missing
    ctx.skew = inst.measure_skew()
    started = time.monotonic()
    log(f"run {run_id}: scenario {sc.name}, {len(sc.steps)} steps, clock skew {ctx.skew.total_seconds():+.3f}s")
    prev_sim = None
    for step in sc.steps:
        if speed == "realtime" and prev_sim is not None:  # SIM-10: soak tests only, never the demo
            time.sleep(max(0.0, (step.sim_time - prev_sim).total_seconds()))
        prev_sim = step.sim_time
        ctx.set_clock(step.sim_time)
        t0 = time.monotonic()
        try:
            registry[step.action].run(ctx, step)
        except Exception as e:  # SIM-05: failures are part of the ground truth
            ctx.truth(step, op=step.action, share=step.params.get("share"), path=step.params.get("path"),
                      expected_event=None, result="error", error=str(e)[:500])
            raise
        if step.id:
            ctx.steps_done[step.id] = step
        who = f"{step.actor} as {step.identity}" if step.actor else "-"
        log(f"  {step.at:9} {step.action:15} {who:30} {time.monotonic() - t0:5.1f}s")
        ctx.settle(0.3)
    atomic_write_json(ctx.run_dir / "run.json", {
        "run_id": run_id, "scenario": sc.name, "seed": seed, "corpus": sc.corpus, "epoch": iso(sc.epoch),
        "steps": len(sc.steps), "duration_s": round(time.monotonic() - started, 1), "finished": iso(utcnow())})
    log(f"run {run_id} finished in {time.monotonic() - started:.1f}s; ground truth: {ctx.run_dir / 'groundtruth.jsonl'}")
    return ctx


def restore(inst: Instance, run_id: str, log=print) -> int:
    """Targeted Restore stand-in: puts back every file the run encrypted (from the corpus pack, as admin) and removes
    the encrypted copies. Planted files and notes are deliberately left in place: that is the gap DwTA closes."""
    run_dir = inst.run / "runs" / run_id
    meta = json.loads((run_dir / "run.json").read_text())
    pack = str(inst.corpus_root / meta["corpus"] / "files")
    by_share: dict[str, list[str]] = {}
    for t in read_jsonl(run_dir / "groundtruth.jsonl"):
        if t.get("encrypted_from"):
            src = t["encrypted_from"]
            by_share.setdefault(t["volume"], []).extend(
                [S.put(f"{pack}/{t['volume']}{t.get('corpus_src', src)}", src), S.delete(t["path"])])
    actor, identity = inst.restore_actor()
    sess = S(inst, actor, identity, "restore")
    n = 0
    for share, cmds in by_share.items():
        sess.run(share, cmds)
        n += len(cmds) // 2
    log(f"restored {n} encrypted files for run {run_id} (planted files left in place)")
    return n


__all__ = ["run", "restore", "resolve_scenario", "keystream"]
