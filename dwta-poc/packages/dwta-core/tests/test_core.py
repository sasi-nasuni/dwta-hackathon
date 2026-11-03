from datetime import UTC, datetime, timedelta

import pytest
from dwta_core.events import FsEvent, event_id
from dwta_core.journal import JournalReader, JournalWriter, Position
from dwta_core.simclock import SimClockReader, append_entry, parse_at
from dwta_core.timeutil import iso, parse_iso

EPOCH = datetime(2026, 11, 2, tzinfo=UTC)


def test_parse_at():
    assert parse_at("D1 09:14", EPOCH) == datetime(2026, 11, 2, 9, 14, tzinfo=UTC)
    assert parse_at("D7 02:00:30", EPOCH) == datetime(2026, 11, 8, 2, 0, 30, tzinfo=UTC)
    for bad in ("D0 01:00", "7 02:00", "D1 24:00"):
        with pytest.raises(ValueError):
            parse_at(bad, EPOCH)


def test_iso_roundtrip():
    dt = datetime(2026, 11, 3, 6, 12, 44, 381000, tzinfo=UTC)
    assert iso(dt) == "2026-11-03T06:12:44.381000Z"
    assert parse_iso(iso(dt)) == dt


def test_simclock_latest_anchor_wins(tmp_path):
    clock = tmp_path / "simclock.jsonl"
    reader = SimClockReader(clock)
    wall = datetime(2026, 11, 3, 6, 0, tzinfo=UTC)
    assert reader.to_sim(wall) == wall  # no clock -> identity
    append_entry(clock, "r1", parse_at("D1 09:14", EPOCH), wall)
    append_entry(clock, "r1", parse_at("D7 02:00", EPOCH), wall + timedelta(seconds=10))
    assert reader.to_sim(wall + timedelta(seconds=3)) == parse_at("D1 09:14", EPOCH) + timedelta(seconds=3)
    assert reader.to_sim(wall + timedelta(seconds=12)) == parse_at("D7 02:00", EPOCH) + timedelta(seconds=2)
    assert reader.to_sim(wall - timedelta(seconds=1)) == wall - timedelta(seconds=1)


def _ev(i: int, ts: str) -> dict:
    return FsEvent(event_id(*("audit", ts, "write_close", "finance", f"/f{i}", "jdoe", "1")), "audit",
                   "write_close", ts, ts, "finance", f"/f{i}", None, False, "jdoe", "10.0.0.1", "WS",
                   "lab", 1, None).to_dict()


def test_event_id_is_deterministic():
    a = event_id("audit", "t", "write_close", "finance", "/a", "u", "1")
    assert a == event_id("audit", "t", "write_close", "finance", "/a", "u", "1")
    assert a != event_id("audit", "t", "write_close", "finance", "/b", "u", "1")


def test_journal_roll_resume_and_read(tmp_path):
    w = JournalWriter(tmp_path, max_bytes=600)
    events = [_ev(i, f"2026-11-03T06:0{i}:00.000000Z") for i in range(6)]
    events.append(_ev(9, "2026-11-03T07:00:00.000000Z"))
    for e in events[:4]:
        w.append(e)
    w.close()
    w = JournalWriter(tmp_path, max_bytes=600)  # resume the open segment
    for e in events[4:]:
        w.append(e)
    w.close()
    reader = JournalReader(tmp_path)
    assert len(reader.segments()) >= 2
    got = list(reader.read())
    assert [e for _, e in got] == events
    mid = got[2][0]
    assert [e for _, e in reader.read(mid)] == events[3:]
    assert list(reader.read(got[-1][0])) == []
    assert (tmp_path / "INDEX").exists()


def test_journal_reader_ignores_partial_line(tmp_path):
    seg = tmp_path / "2026-11-03" / "06-000.jsonl"
    seg.parent.mkdir()
    seg.write_text('{"a":1}\n{"a":2')
    assert [e for _, e in JournalReader(tmp_path).read(Position())] == [{"a": 1}]
