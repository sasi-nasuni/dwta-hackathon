"""``dwta-incident``: incident intake service and the admin's pre-restore review commands."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from dwta_core import log as dlog
from dwta_core.fileio import atomic_write_json
from dwta_core.simclock import parse_at
from dwta_core.timeutil import iso, parse_iso
from dwta_ledger.common import publish_alerts
from dwta_ledger.db import connect
from dwta_ledger.migrate import check_schema

from .av import scanner_from_env
from .engine import MODES, Engine
from .intake import IncidentError, process_inbox, set_restore_time

INCIDENTS = Path(os.environ.get("DWTA_INCIDENTS_DIR", "/lab/incidents"))
RUN = Path(os.environ.get("DWTA_RUN_DIR", "/lab/run"))
EPOCH = parse_iso(os.environ.get("SIM_EPOCH", "2026-11-02T00:00:00Z"))


def _sim(text: str):
    """Accepts 'D7 02:05' (simulated) or an ISO timestamp."""
    return parse_at(text, EPOCH) if text.strip().upper().startswith("D") else parse_iso(text)


def serve() -> int:
    log = dlog.setup("incident")
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    for d in ("inbox", "processed", "rejected"):
        (INCIDENTS / d).mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        check_schema(conn)
        engine = Engine(conn, RUN, scanner_from_env())
        log.info("incident service started", extra=dlog.kv(av_scanner=engine.scanner.name))
        while not stop:
            process_inbox(conn, INCIDENTS, engine)
            time.sleep(1.0)
    return 0


def _print_review(doc: dict, mode: str) -> None:
    w = doc["window"]
    print(f"incident {doc['incident_id']}  window {w['from']} -> {w['to']}  mode {mode}"
          f"{'  (INCOMPLETE)' if doc['incomplete'] else ''}")
    print(f"{'#':>3} {'level':7} {'score':>5} {'av':12} {'decision':9} {'change':10} item")
    for it in doc["modes"][mode]:
        what = it.get("path") or f"{it['item_kind']} ({it.get('count')} files, e.g. {', '.join(it.get('samples', [])[:2])})"
        sigs = ",".join(r["signal"] for r in it["reasons"])
        av = (it.get("av") or {}).get("verdict") or "-"
        print(f"{it['rank']:>3} {it['suspicion_level']:7} {it['score']:>5} {av:12} {it['decision']:9} {it['change_kind'] or '':10} "
              f"{what}  [{sigs}]")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dwta-incident", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the intake service")
    r = sub.add_parser("raise", help="raise an incident like the product's detector would (writes to the inbox)")
    r.add_argument("--detected", required=True, help="'D7 02:05' or ISO time")
    r.add_argument("--user")
    r.add_argument("--ip")
    r.add_argument("--machine")
    r.add_argument("--volume", action="append", required=True)
    r.add_argument("--restore-time", help="admin input; may be given later with set-restore-time")
    r.add_argument("--id")
    srt = sub.add_parser("set-restore-time", help="admin: latest moment with no attacker presence")
    srt.add_argument("incident_id")
    srt.add_argument("restore_time")
    sh = sub.add_parser("show", help="print the review list")
    sh.add_argument("incident_id")
    sh.add_argument("--mode", choices=MODES, default="rules")
    sub.add_parser("list", help="list incidents")
    d = sub.add_parser("decide", help="admin decision for one item: remove (keep out of the recovery) or keep")
    d.add_argument("incident_id")
    d.add_argument("item", help="rank in the chosen mode, or item_key")
    d.add_argument("decision", choices=["remove", "keep"])
    d.add_argument("--by", required=True)
    d.add_argument("--mode", choices=MODES, default="rules")
    f = sub.add_parser("finalize", help="lock decisions and write the restore-exclusion manifest")
    f.add_argument("incident_id")
    f.add_argument("--by", required=True)
    f.add_argument("--mode", choices=MODES, default="rules")
    rp = sub.add_parser("replan", help="re-rank with the current configuration")
    rp.add_argument("incident_id")
    args = p.parse_args(argv)

    if args.cmd == "serve":
        return serve()
    if args.cmd == "raise":
        rec = {"schema": "dwta.incident/v1", "incident_id": args.id or f"inc-cli-{int(time.time())}", "source": "cli",
               "kind": "ransomware", "detected_sim_ts": iso(_sim(args.detected)), "user": args.user,
               "client_ip": args.ip, "client_name": args.machine, "volumes": args.volume,
               "restore_time_sim_ts": iso(_sim(args.restore_time)) if args.restore_time else None,
               "description": "raised from the CLI"}
        atomic_write_json(INCIDENTS / "inbox" / f"{rec['incident_id']}.json", rec)
        print(rec["incident_id"])
        return 0

    dlog.setup("incident-cli")
    try:
        with connect() as conn:
            check_schema(conn)
            engine = Engine(conn, RUN, scanner_from_env())
            if args.cmd == "list":
                for i in conn.execute("SELECT incident_id, state, detected_sim_ts, restore_time_sim_ts, \"user\", "
                                      "reject_reason FROM incidents ORDER BY created_at"):
                    print(f"{i['incident_id']:36} {i['state']:22} detected {iso(i['detected_sim_ts'])} restore "
                          f"{iso(i['restore_time_sim_ts']) if i['restore_time_sim_ts'] else '-':28} {i['reject_reason'] or ''}")
                return 0
            if args.cmd == "set-restore-time":
                with conn.transaction():
                    set_restore_time(conn, args.incident_id, _sim(args.restore_time))
                out = engine.review(args.incident_id)
                publish_alerts(RUN, "incident", [out["alert"]] if out["alert"] else [])
                _print_review(out["doc"], "rules")
                return 0
            if args.cmd == "replan":
                _print_review(engine.review(args.incident_id, wait=False)["doc"], "rules")
                return 0
            if args.cmd == "show":
                path = RUN / "incidents" / args.incident_id / "review-list.json"
                doc = json.loads(path.read_text())
                # refresh decisions from the ledger
                dec = {r["item_key"]: r["decision"] for r in conn.execute(
                    "SELECT item_key, decision FROM review_decisions WHERE incident_id = %s", (args.incident_id,))}
                for items in doc["modes"].values():
                    for it in items:
                        it["decision"] = dec.get(it["item_key"], "pending")
                _print_review(doc, args.mode)
                return 0
            if args.cmd == "decide":
                key = engine.decide(args.incident_id, args.item, args.decision, args.by, args.mode)
                print(f"{key}: {args.decision} (by {args.by})")
                return 0
            if args.cmd == "finalize":
                m = engine.finalize(args.incident_id, args.by, args.mode)
                print(json.dumps(m["summary"]))
                print(f"restore-exclusion manifest: {RUN / 'incidents' / args.incident_id / 'restore-exclusions.json'}")
                return 0
    except (IncidentError, PermissionError, ValueError, KeyError, FileNotFoundError) as e:
        print(f"dwta-incident: {e}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
