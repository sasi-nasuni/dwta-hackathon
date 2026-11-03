"""``dwta-ledger``: schema migrations and a quick status view."""

from __future__ import annotations

import argparse
import sys

from dwta_core import log as dlog

from .db import connect
from .migrate import migrate


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dwta-ledger", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="create roles and apply pending migrations (idempotent)")
    sub.add_parser("status", help="row counts per table")
    args = p.parse_args(argv)
    log = dlog.setup("ledger")
    with connect() as conn:
        if args.cmd == "migrate":
            applied = migrate(conn)
            log.info("migrations applied", extra=dlog.kv(applied=applied))
            return 0
        if args.cmd == "status":
            for t in ("files", "artifacts", "feed_entries", "feed_matches", "incidents", "review_items",
                      "review_decisions", "alerts"):
                n = conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"]
                sys.stdout.write(f"{t:18} {n}\n")
            return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
