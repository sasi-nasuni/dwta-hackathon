"""Classifier service loop (B5): journal -> pipeline -> ledger, exactly once (CLS-05)."""

from __future__ import annotations

import logging
import os
import signal
import time
from pathlib import Path

from dwta_core import log as dlog
from dwta_core.config import load_config, specs_dir
from dwta_core.journal import JournalReader, Position
from dwta_core.timeutil import parse_iso, utcnow
from dwta_ledger.common import get_offset, publish_alerts, set_offset
from dwta_ledger.db import connect
from dwta_ledger.migrate import check_schema

from . import __version__
from .analyzers import OletoolsAnalyzer, YaraAnalyzer
from .content import ReadBudget, SinglePass
from .pipeline import Config, Pipeline
from .typers import MagikaTyper, RulesTyper

CONSUMER = "classifier"


def build_pipeline(data_dir: Path) -> Pipeline:
    log = logging.getLogger("classifier")
    cfgs = {n: load_config(n) for n in ("magic", "ext_map", "magika_map", "rules", "read_budget", "lab")}
    magika = None
    if os.environ.get("CLASSIFIER_AI", "on") != "off":
        try:
            magika = MagikaTyper(cfgs["magika_map"].data["label"])
        except Exception as e:  # CLS-06
            log.warning("Magika unavailable, rules only: %s", e)
    version = f"{__version__}+" + "".join(cfgs[n].sha256[:4] for n in sorted(cfgs))
    cfg = Config(data_dir, {k: v["kind"] for k, v in cfgs["lab"].data["shares"].items()}, cfgs["ext_map"].data["ext"],
                 cfgs["rules"].data, float(cfgs["magika_map"].data.get("min_score", 0.8)), version)
    return Pipeline(cfg, SinglePass(ReadBudget.from_config(cfgs["read_budget"].data)), RulesTyper(cfgs["magic"].data),
                    magika, OletoolsAnalyzer(), YaraAnalyzer(specs_dir() / "yara"))


def main() -> None:
    log = dlog.setup("classifier")
    run_dir = Path(os.environ.get("DWTA_RUN_DIR", "/lab/run"))
    pipeline = build_pipeline(Path(os.environ.get("DWTA_DATA_DIR", "/lab/data")))
    reader = JournalReader(run_dir / "journal")
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    with connect() as conn:
        check_schema(conn)
        off = get_offset(conn, CONSUMER)
        pos = Position(off["segment"], off["line"])
        log.info("classifier started", extra=dlog.kv(position=f"{pos.segment}:{pos.line}", ai=pipeline.magika is not None,
                                                      version=pipeline.cfg.version))
        while not stop:
            batch = list(reader.read(pos, limit=200))
            if not batch:
                with conn.transaction():  # caught up: advance the barrier clock (spec §5.10.1)
                    set_offset(conn, CONSUMER, pos.segment, pos.line, utcnow(), None)
                time.sleep(0.3)
                continue
            alerts = []
            with conn.transaction():
                for p, ev in batch:
                    alerts += pipeline.handle(conn, ev)
                    pos = p
                last = batch[-1][1]
                set_offset(conn, CONSUMER, pos.segment, pos.line, parse_iso(last["ts"]), parse_iso(last["sim_ts"]))
            publish_alerts(run_dir, CONSUMER, alerts)
            for a in alerts:
                log.info("alert", extra=dlog.kv(kind=a["kind"], severity=a["severity"], mode=a["mode"],
                                                 rules=a["rule_ids"], artifact_id=a["artifact_id"]))
    log.info("classifier stopped")


if __name__ == "__main__":
    main()
