"""``dwta-lab``: create, start, stop and inspect lab instances."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time

from .lab import Instance, init_instance, status

SERVICES_LONG_RUNNING = ("samba", "client-admin", "client-jdoe", "client-asmith", "client-attack",
                         "collector", "ledger", "classifier", "matcher", "incident")


def _wait_ready(inst: Instance, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = {r["Service"]: r for r in status(inst)}
        migrate = rows.get("ledger-migrate", {})
        if migrate.get("State") == "exited" and migrate.get("ExitCode", 0) != 0:
            print("ledger-migrate failed; see: dwta-lab logs ledger-migrate", file=sys.stderr)
            return False
        ok = all(
            rows.get(s, {}).get("State") == "running" and rows[s].get("Health", "") in ("", "healthy")
            for s in SERVICES_LONG_RUNNING
        )
        if ok:
            return True
        time.sleep(2)
    return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dwta-lab", description=__doc__)
    p.add_argument("--instance", "-i", default="dwta1", help="lab instance name (default dwta1)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create lab/<instance>/ with .env, secrets and folders (idempotent)")
    up = sub.add_parser("up", help="build images and start the lab")
    up.add_argument("--no-build", action="store_true")
    up.add_argument("--timeout", type=float, default=180)
    down = sub.add_parser("down", help="stop the lab")
    down.add_argument("--volumes", action="store_true", help="also delete the ledger volume")
    sub.add_parser("status", help="show containers")
    sub.add_parser("export-ledger", help="pg_dump the ledger to lab/<instance>/run/ledger-<ts>.sql (LED-06)")
    sub.add_parser("reset", help="wipe shares, logs, journal, feeds, incidents and the ledger; keep .env and secrets")
    logs = sub.add_parser("logs", help="show service logs")
    logs.add_argument("service", nargs="*")
    comp = sub.add_parser("compose", help="pass arguments to docker compose for this instance")
    comp.add_argument("args", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)

    if args.cmd == "init":
        inst = init_instance(args.instance)
        env = inst.env()
        print(f"instance {inst.name}: {inst.root}")
        print(f"  SMB endpoint  smb://<identity>@127.0.0.1:{env['SMB_PORT']}/<share>")
        print(f"  lab subnet    {env['LAB_SUBNET']}")
        return 0

    inst = Instance.get(args.instance)
    if args.cmd == "up":
        if not inst.env_file.exists():
            init_instance(args.instance)
        cmd = ["up", "-d"] + ([] if args.no_build else ["--build"])
        inst.compose(*cmd)
        if not _wait_ready(inst, args.timeout):
            print("lab did not become ready in time; see `dwta-lab status`", file=sys.stderr)
            return 1
        print(f"lab {inst.name} is up (SMB on 127.0.0.1:{inst.env()['SMB_PORT']})")
        return 0
    if args.cmd == "down":
        inst.compose("down", *(["--volumes"] if args.volumes else []))
        return 0
    if args.cmd == "reset":
        import shutil
        if inst.env_file.exists():
            inst.compose("down", "--volumes")
        for d in (inst.data, inst.logs, inst.run, inst.feeds, inst.incidents):
            shutil.rmtree(d, ignore_errors=True)
        init_instance(args.instance)
        print(f"lab {inst.name} reset; start it with `dwta-lab up`")
        return 0
    if args.cmd == "export-ledger":
        from datetime import UTC, datetime
        out = inst.run / f"ledger-{datetime.now(UTC):%Y%m%d-%H%M%S}.sql"
        dump = inst.compose("exec", "-T", "ledger", "pg_dump", "-U", "dwta_admin", "-d", "dwta", capture=True)
        out.write_bytes(dump.stdout)
        print(f"ledger exported to {out} ({len(dump.stdout)} bytes)")
        return 0
    if args.cmd == "status":
        for r in status(inst):
            print(f"{r['Service']:16} {r['State']:10} {r.get('Health', ''):10} {r.get('Status', '')}")
        return 0
    if args.cmd == "logs":
        return subprocess.call(inst.compose_cmd("logs", "--no-color", "--tail", "200", *args.service))
    if args.cmd == "compose":
        return subprocess.call(inst.compose_cmd(*args.args))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
