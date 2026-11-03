"""Threat intelligence and incident actions (not SMB operations): publish_feed (B7) and raise_incident (B9)."""

from __future__ import annotations

import hashlib
import random

from dwta_core.fileio import atomic_write_json, atomic_write_text
from dwta_core.simclock import parse_at
from dwta_core.timeutil import iso

from .. import artifacts
from ..scenario import ScenarioError, Step
from . import action

FEED_COLUMNS = ("first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess",
                "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh")


def _csv_row(values: list[str]) -> str:
    return ",".join('"' + v.replace('"', "") + '"' for v in values)


@action("publish_feed", needs_actor=False)
def publish_feed(ctx, step: Step) -> None:
    """Fabricated feed in MalwareBazaar CSV export format (FEED-01/02), dropped atomically into feeds/inbox."""
    first_seen = ctx.sim_now().strftime("%Y-%m-%d %H:%M:%S")
    rng = random.Random(f"{ctx.seed}:feed:{step.index}")
    rows, hashes, expected = [], [], []
    for name in step.params.get("include_artifacts", []):
        data = artifacts.get(name)
        sha = hashlib.sha256(data).hexdigest()
        hashes.append(sha)
        expected.append(sha)
        rows.append([first_seen, sha, hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), "dwta-lab",
                     step.params.get("file_name", f"{name}.bin"), "exe", "application/x-dosexec", "DwTA.TestFamily",
                     "n/a", "n/a", "n/a", "n/a", "n/a"])
    for _ in range(int(step.params.get("decoys", 0))):
        sha = f"{rng.getrandbits(256):064x}"
        hashes.append(sha)
        rows.append([first_seen, sha, f"{rng.getrandbits(128):032x}", f"{rng.getrandbits(160):040x}", "dwta-lab",
                     "decoy.bin", "exe", "application/x-dosexec", "DwTA.Decoy", "n/a", "n/a", "n/a", "n/a", "n/a"])
    text = ("# DwTA fabricated feed (MalwareBazaar export format)\n# " + ",".join(FEED_COLUMNS) + "\n"
            + "".join(_csv_row(r) + "\n" for r in rows))
    name = f"feed-{ctx.sim_now():%Y%m%d}-{ctx.run_id}-{step.index}.csv"
    atomic_write_text(ctx.instance.feeds / "inbox" / name, text)
    ctx.truth(step, op="publish_feed", share=None, path=f"feeds/inbox/{name}", expected_event=None,
              hashes=len(hashes), expected_matches=expected)


def _validate_incident(step: Step) -> None:
    if "from_step" not in step.params and not {"user", "client_ip"} <= step.params.keys():
        raise ScenarioError(f"step {step.index}: raise_incident needs from_step, or user + client_ip")


@action("raise_incident", needs_actor=False, validate=_validate_incident)
def raise_incident(ctx, step: Step) -> None:
    """Stand-in for Ransomware Protection (D-18) + the admin's restore time (D-24)."""
    p = step.params
    user, ip, machine, volumes = p.get("user"), p.get("client_ip"), p.get("client_name"), p.get("volumes")
    if "from_step" in p:
        src = ctx.steps_done[p["from_step"]]
        actor = ctx.lab["actors"][src.actor]
        user = user or src.identity
        ip = ip or ctx.env[f"IP_{src.actor.upper().replace('-', '_')}"]
        machine = machine or actor["netbios"]
        volumes = volumes or [src.params["share"]]
    restore = p.get("restore_time")
    incident = {
        "schema": "dwta.incident/v1",
        "incident_id": p.get("incident_id", f"inc-{ctx.run_id}-{step.index}"),
        "source": "scenario", "kind": "ransomware",
        "detected_sim_ts": iso(ctx.sim_now()),
        "user": user, "client_ip": ip, "client_name": machine, "volumes": volumes or [],
        "restore_time_sim_ts": iso(parse_at(restore, ctx.scenario.epoch)) if restore else None,
        "description": p.get("description", "Mass encryption detected (simulated Ransomware Protection alert)"),
    }
    atomic_write_json(ctx.instance.incidents / "inbox" / f"{incident['incident_id']}.json", incident)
    ctx.truth(step, op="raise_incident", share=None, path=f"incidents/inbox/{incident['incident_id']}.json",
              expected_event=None, incident_id=incident["incident_id"])
