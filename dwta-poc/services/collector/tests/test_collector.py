from pathlib import Path

from dwta_collector.audit import parse_line
from dwta_collector.correlator import Correlator
from dwta_collector.main import Collector, Settings
from dwta_core.journal import JournalReader

FIXTURE = Path(__file__).parent / "fixtures" / "office_save.log"


def _events():
    corr = Correlator(rename_window=5)
    out, unparsed = [], 0
    for line in FIXTURE.read_text().splitlines(keepends=True):
        rec = parse_line(line)
        if rec is None:
            unparsed += 1
            continue
        out += corr.feed(rec) + corr.expire(rec.ts)
    return out, corr, unparsed


def test_parse_line_fields():
    rec = parse_line(FIXTURE.read_text().splitlines()[4])
    assert (rec.user, rec.client_ip, rec.client_name, rec.share, rec.pid, rec.op) == (
        "jdoe", "10.250.1.21", "WS-JDOE01", "finance", "133", "create_file")
    assert rec.ts.microsecond == 817911


def test_correlation_sequence():
    events, corr, unparsed = _events()
    got = [(e.op, e.path, e.prev_path, e.via_rename, e.rec.user) for e in events]
    assert got == [
        ("mkdir", "/Q3", None, False, "jdoe"),
        ("write_close", "/Q3/report.docx", "/Q3/~WRL0001.tmp", True, "jdoe"),   # office save = ONE event
        ("write_close", "/notes.txt", None, False, "svc-backup"),
        ("rename", "/notes.txt.dwtalocked", "/notes.txt", False, "svc-backup"),
        ("delete", "/old.csv", None, False, "svc-backup"),
        ("write_close", "/orphan.tmp", None, False, "jdoe"),                    # temp never renamed: window expired
    ]
    assert corr.ignored == 1   # ._notes.txt
    assert unparsed == 1


def test_collector_replay_is_deterministic(tmp_path):
    def run(run_dir: Path) -> bytes:
        s = Settings(FIXTURE, tmp_path / "data", run_dir, "/srv/shares", "10.250.1.0/24", "10.250.1.1",
                     "audit", 5.0, "journal")
        c = Collector(s)
        while c.step_audit():
            pass
        c.checkpoint()
        c.journal.close()
        return b"".join(p.read_bytes() for p in sorted((run_dir / "journal").glob("*/*.jsonl")))

    a, b = run(tmp_path / "r1"), run(tmp_path / "r2")
    assert a == b and a.count(b"\n") == 6
    events = [e for _, e in JournalReader(tmp_path / "r1" / "journal").read()]
    assert {e["client_origin"] for e in events} == {"lab"}


def test_collector_restart_has_no_duplicates(tmp_path):
    s = Settings(FIXTURE, tmp_path / "data", tmp_path / "run", "/srv/shares", "10.250.1.0/24", "10.250.1.1",
                 "audit", 5.0, "journal")
    c = Collector(s)
    c.tailer.read_lines(max_bytes=1500)   # crash mid-file: state saved at a "safe" offset
    c.tailer.state.offset = 0
    while c.step_audit():
        pass
    c.checkpoint()
    c.journal.close()
    c2 = Collector(s)                      # restart: re-reads from the safe offset
    c2.tailer.state.offset = 0             # worst case: replay everything
    while c2.step_audit():
        pass
    c2.checkpoint()
    c2.journal.close()
    ids = [e["event_id"] for _, e in JournalReader(tmp_path / "run" / "journal").read()]
    assert len(ids) == len(set(ids)) == 6


def test_tailer_survives_rotation(tmp_path):
    from dwta_collector.tailer import AuditTailer
    log = tmp_path / "audit.log"
    log.write_text("a\nb\n")
    t = AuditTailer(log, tmp_path / "state")
    assert [x[1] for x in t.read_lines()] == ["a\n", "b\n"]
    with log.open("a") as fh:
        fh.write("c\n")                  # written just before rotation, not yet read
    log.rename(tmp_path / "audit.log.old")
    log.write_text("d\n")
    assert [x[1] for x in t.read_lines()] == ["c\n"]   # old file drained first
    assert [x[1] for x in t.read_lines()] == ["d\n"]
