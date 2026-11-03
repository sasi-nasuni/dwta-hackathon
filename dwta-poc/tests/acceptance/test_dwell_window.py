"""End-to-end acceptance on the running Docker lab (marker ``lab``): the dwell-window story + pre-restore review.

Run with ``make acceptance`` (resets the lab instance ``dwta-at``, so it never touches ``dwta1``).
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest
from dwta_core.fileio import read_jsonl
from dwta_sim import lab_cli, runner
from dwta_sim.lab import Instance
from dwta_sim.scenario import load
from dwta_sim.score import score

pytestmark = pytest.mark.lab
INSTANCE = "dwta-at"


def _wait_for(path: Path, timeout: float = 90) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return path
        time.sleep(1)
    raise TimeoutError(path)


def _incident_cli(inst: Instance, *args: str) -> subprocess.CompletedProcess:
    return inst.compose("exec", "-T", "incident", "dwta-incident", *args, check=False, capture=True)


def _run_story(inst: Instance) -> dict:
    assert lab_cli.main(["--instance", INSTANCE, "reset"]) == 0
    assert lab_cli.main(["--instance", INSTANCE, "up", "--timeout", "300"]) == 0
    ctx = runner.run(inst, load(runner.resolve_scenario("dwell-window")), seed=42, log=lambda *_: None)
    incident_id = next(t["incident_id"] for t in read_jsonl(ctx.run_dir / "groundtruth.jsonl") if t["op"] == "raise_incident")
    review = json.loads(_wait_for(inst.run / "incidents" / incident_id / "review-list.json").read_text())
    time.sleep(3)
    return {"ctx": ctx, "incident_id": incident_id, "review": review}


@pytest.fixture(scope="module")
def story():
    inst = Instance.get(INSTANCE)
    out = _run_story(inst)
    out["inst"] = inst
    yield out
    inst.compose("down", "--volumes", check=False)


def _alerts(inst: Instance) -> list[dict]:
    return [a for f in sorted((inst.run / "alerts").glob("*.jsonl")) for a in read_jsonl(f)]


def test_collector_matches_ground_truth(story):          # AT-07 / AT-14
    r = score(story["inst"], story["ctx"].run_id)
    assert r["recall"] == 1.0 and not r["extra_events"] and not r["wrong_attribution"], r
    assert r["max_sim_ts_deviation_s"] < 1.0


def test_day1_write_time_alert(story):                    # AT-17
    hits = [a for a in _alerts(story["inst"]) if a["kind"] == "write_time" and a["reasons"][0]["path"] == "/Q3/Q3-Report.pdf"]
    assert [(a["rule_ids"], a["severity"]) for a in hits] == [(["R-W2"], "high")]


def test_day5_feed_match(story):                          # AT-29
    hits = [a for a in _alerts(story["inst"]) if a["kind"] == "feed_match"]
    assert len(hits) == 1 and hits[0]["reasons"][0]["path"] == "/Q3/Q3-Report.pdf"
    assert hits[0]["sim_ts"].startswith("2026-11-06T10:00")


def test_day7_pre_restore_review(story):                  # AT-32, AT-40
    for mode in ("rules", "rules_ai"):
        items = story["review"]["modes"][mode]
        assert items[0]["path"] == "/Q3/Q3-Report.pdf" and items[0]["score"] == 230 and items[0]["suspicion_level"] == "high"
        assert [i["item_kind"] for i in items] == ["file", "attack_outputs_group"], items
        assert items[1]["count"] == 44
        assert items[0]["av"]["verdict"] == "not_scanned" and "av" not in items[1]   # step ⑤ hook (AT-41)


def test_decisions_finalize_and_manifest(story):          # AT-38, AT-39
    inst, iid = story["inst"], story["incident_id"]
    refused = _incident_cli(inst, "finalize", iid, "--by", "admin")
    assert refused.returncode != 0 and b"pending" in refused.stderr
    assert _incident_cli(inst, "decide", iid, "1", "remove", "--by", "admin").returncode == 0
    assert _incident_cli(inst, "decide", iid, "2", "remove", "--by", "admin").returncode == 0
    assert _incident_cli(inst, "finalize", iid, "--by", "admin").returncode == 0
    m = json.loads((inst.run / "incidents" / iid / "restore-exclusions.json").read_text())
    assert m["summary"] == {"listed": 2, "remove": 2, "keep": 0}
    assert m["remove"][0]["path"] == "/Q3/Q3-Report.pdf" and m["remove"][0]["action"] == "quarantine"
    locked = _incident_cli(inst, "decide", iid, "1", "keep", "--by", "admin")
    assert locked.returncode != 0 and b"finalized" in locked.stderr
    assert (inst.data / "finance" / "Q3" / "Q3-Report.pdf").exists()   # v1 never touches files


def test_restore_stand_in_leaves_planted_file(story):
    inst = story["inst"]
    assert runner.restore(inst, story["ctx"].run_id, log=lambda *_: None) == 40
    q3 = {p.name for p in (inst.data / "finance" / "Q3").iterdir()}
    assert "Q3-Report.pdf" in q3 and not any(n.endswith(".dwtalocked") for n in q3)
