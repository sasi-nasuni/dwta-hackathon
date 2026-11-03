from dwta_matcher.main import parse_feed

GOOD = "a" * 64


def test_parse_feed_malwarebazaar_format():
    text = ("# MalwareBazaar style\n# first_seen_utc,sha256_hash,...\n"
            f'"2026-11-06 10:00:00","{GOOD.upper()}","m","s","dwta-lab","Q3-Report.pdf","exe","x","DwTA.TestFamily","n/a"\n'
            '"2026-11-06 10:00:00","not-a-hash","m"\n'
            '"x"\n')
    rows, rejects = parse_feed(text)
    assert [r["sha256"] for r in rows] == [GOOD]
    assert rows[0]["first_seen"].isoformat() == "2026-11-06T10:00:00+00:00"
    assert [r["reason"] for r in rejects] == ["bad sha256", "too few columns"]


def test_feed_severities_come_from_config():
    from dwta_core.config import load_config
    rules = load_config("rules").data["rule"]
    assert rules["R-W5"]["severity"] == "critical" and rules["FEED-MATCH"]["severity"] == "critical"
