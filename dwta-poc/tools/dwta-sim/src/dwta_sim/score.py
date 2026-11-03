"""Scores the collector's journal against a run's ground truth (AT-07, AT-14): recall, duplicates, attribution."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from dwta_core.fileio import read_jsonl
from dwta_core.journal import JournalReader
from dwta_core.timeutil import parse_iso

from .lab import Instance

WINDOW = timedelta(seconds=10)


def score(inst: Instance, run_id: str, source: str = "audit") -> dict:
    truth = [t for t in read_jsonl(inst.run / "runs" / run_id / "groundtruth.jsonl") if t.get("expected_event")]
    if not truth:
        raise ValueError(f"no ground truth for {run_id}")
    lo = min(parse_iso(t["wall_ts"]) for t in truth) - WINDOW
    hi = max(parse_iso(t["wall_ts"]) for t in truth) + WINDOW
    events = [e for _, e in JournalReader(inst.run / "journal").read(limit=10**9)
              if e["source"] == source and lo <= parse_iso(e["ts"]) <= hi]
    by_key: dict[tuple, list[dict]] = {}
    for e in events:
        by_key.setdefault((e["volume"], e["path"], e["op"]), []).append(e)
    used: Counter = Counter()
    missing, wrong_attr, sim_dev = [], [], []
    for t in truth:
        cands = by_key.get((t["volume"], t["path"], t["expected_event"]), [])
        cands = [e for e in cands if abs(parse_iso(e["ts"]) - parse_iso(t["wall_ts"])) <= WINDOW]
        match = next((e for e in cands if used[e["event_id"]] == 0), None)
        if match is None:
            missing.append(f"{t['expected_event']} {t['volume']}{t['path']}")
            continue
        used[match["event_id"]] += 1
        if source == "audit" and (match["user"], match["client_ip"], match["client_name"]) != (
                t["identity"], t["client_ip"], t["client_name"]):
            wrong_attr.append(f"{t['path']}: {match['user']}/{match['client_ip']}/{match['client_name']}")
        sim_dev.append(abs((parse_iso(match["sim_ts"]) - parse_iso(t["sim_ts"])).total_seconds()))
    unmatched = [f"{e['op']} {e['volume']}{e['path']}" for e in events if used[e["event_id"]] == 0]
    return {"run_id": run_id, "source": source, "expected": len(truth), "matched": len(truth) - len(missing),
            "recall": round((len(truth) - len(missing)) / len(truth), 4), "missing": missing,
            "extra_events": unmatched, "wrong_attribution": wrong_attr,
            "max_sim_ts_deviation_s": round(max(sim_dev, default=0.0), 3)}
