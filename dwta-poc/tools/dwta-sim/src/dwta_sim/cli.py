"""``dwta-sim``: safe, scenario-driven attack simulator (B3)."""

from __future__ import annotations

import argparse
import sys

from dwta_core.config import load_config

from . import corpus, runner
from .actions import load_all
from .lab import Instance, repo_root
from .scenario import ScenarioError, from_dict, load, validate


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dwta-sim", description=__doc__)
    p.add_argument("--instance", "-i", default="dwta1")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("corpus", help="build or verify a corpus pack (once, outside any run)")
    csub = c.add_subparsers(dest="corpus_cmd", required=True)
    b = csub.add_parser("build")
    b.add_argument("--profile", default="default")
    b.add_argument("--seed", type=int, default=42)
    v = csub.add_parser("verify")
    v.add_argument("pack", nargs="?", default="default-42")

    sub.add_parser("list", help="scenarios and actions")
    val = sub.add_parser("validate", help="check a scenario without running it")
    val.add_argument("scenario")
    r = sub.add_parser("run", help="run a scenario (name in scenarios/ or a path)")
    r.add_argument("scenario")
    r.add_argument("--seed", type=int, default=42)
    r.add_argument("--speed", choices=["max", "realtime"], default="max",
                   help="max = steps back to back (default); realtime = wait simulated time between steps")
    rs = sub.add_parser("restore", help="Targeted Restore stand-in: put back the files a run encrypted")
    rs.add_argument("run_id")
    sc_ = sub.add_parser("score", help="compare the collector's journal with a run's ground truth")
    sc_.add_argument("run_id")
    sc_.add_argument("--source", default="audit", choices=["audit", "watcher"])
    st = sub.add_parser("step", help="run one ad-hoc action, e.g. a second payload")
    st.add_argument("action")
    st.add_argument("--at", required=True, help="simulated time, e.g. 'D7 02:01'")
    st.add_argument("--actor")
    st.add_argument("--as", dest="identity")
    st.add_argument("--param", "-p", action="append", default=[], help="key=value (repeatable)")
    st.add_argument("--corpus", default="default-42")
    args = p.parse_args(argv)

    try:
        if args.cmd == "corpus":
            out = repo_root() / "lab" / "corpus"
            if args.corpus_cmd == "build":
                pack = corpus.build(out, args.profile, args.seed)
                n = len(corpus.load_manifest(pack)["files"])
                print(f"built {pack.name}: {n} files in {pack}")
                return 0
            bad = corpus.verify(out / args.pack)
            print("ok" if not bad else f"{len(bad)} files differ: {bad[:5]}")
            return 0 if not bad else 1
        if args.cmd == "list":
            print("scenarios:", ", ".join(sorted(x.stem for x in (repo_root() / "scenarios").glob("*.toml"))))
            print("actions:  ", ", ".join(sorted(load_all())))
            return 0
        inst = Instance.get(args.instance)
        if args.cmd == "validate":
            sc = load(runner.resolve_scenario(args.scenario))
            validate(sc, load_config("lab").data, load_all())
            print(f"{sc.name}: {len(sc.steps)} steps OK")
            return 0
        if args.cmd == "run":
            sc = load(runner.resolve_scenario(args.scenario), inst.env().get("SIM_EPOCH", "2026-11-02T00:00:00Z"))
            runner.run(inst, sc, args.seed, speed=args.speed)
            return 0
        if args.cmd == "restore":
            runner.restore(inst, args.run_id)
            return 0
        if args.cmd == "score":
            import json as _json

            from .score import score
            result = score(inst, args.run_id, args.source)
            print(_json.dumps(result, indent=1))
            return 0 if result["recall"] == 1.0 and not result["extra_events"] and not result["wrong_attribution"] else 1
        if args.cmd == "step":
            raw = {"at": args.at, "action": args.action}
            if args.actor:
                raw["actor"] = args.actor
            if args.identity:
                raw["as"] = args.identity
            for kv in args.param:
                k, _, val = kv.partition("=")
                raw[k] = int(val) if val.isdigit() else val
            sc = from_dict({"name": f"adhoc-{args.action}", "corpus": args.corpus, "step": [raw]},
                           inst.env().get("SIM_EPOCH", "2026-11-02T00:00:00Z"))
            runner.run(inst, sc)
            return 0
    except (ScenarioError, runner.SafetyError, FileNotFoundError, KeyError) as e:
        print(f"dwta-sim: {e}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
