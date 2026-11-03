from dwta_core.config import load_config
from dwta_incident.engine import is_attack_output, level_for, score_artifact

RANK = load_config("ranking").data
OUT = load_config("attack_outputs").data
EXEC = set(load_config("rules").data["executable_classes"])
INC = {"user": "svc-backup", "client_ip": "10.250.1.66", "client_name": "SRV-BKP01"}


def art(**kw):
    base = dict(artifact_id=17, prev_artifact_id=None, user="svc-backup", client_ip="10.250.1.66", client_name="SRV-BKP01",
                share_kind="document", type_rules="pe_binary", type_ai="pe_binary", ai_score=0.99, ext="pdf",
                ext_mismatch_rules=True, ext_mismatch_ai=True, prev_type_rules=None, prev_type_ai=None, signals=[])
    base.update(kw)
    return base


def test_planted_pe_scores_230_high():
    score, reasons = score_artifact(art(), INC, "rules", RANK, EXEC, 0.8, [4])
    assert score == 230
    assert [r["signal"] for r in reasons] == ["S-FEED", "S-USER", "S-IP", "S-HOST", "S-EXEC-DOC", "S-EXT"]
    assert level_for(score, RANK["levels"]) == "high"


def test_legit_edit_not_listed():
    score, _ = score_artifact(art(user="jdoe", client_ip="10.250.1.21", client_name="WS-JDOE01", type_rules="office_doc",
                                  type_ai="office_doc", ext="docx", ext_mismatch_rules=False, ext_mismatch_ai=False),
                              INC, "rules", RANK, EXEC, 0.8, [])
    assert score < RANK["min_score"] and level_for(score, RANK["levels"]) is None


def test_type_change_signal_and_ai_fallback():
    a = art(prev_artifact_id=9, prev_type_rules="pdf", prev_type_ai="pdf", user="jdoe", client_ip="x", client_name="y")
    score, reasons = score_artifact(a, INC, "rules", RANK, EXEC, 0.8, [])
    assert "S-TYPE-CHANGE" in [r["signal"] for r in reasons] and score == 90
    low_conf = art(type_ai="text", ai_score=0.3)      # Magika unsure -> rules typing is used
    assert score_artifact(low_conf, INC, "rules_ai", RANK, EXEC, 0.8, [])[0] == 130


def _c(path, user="svc-backup", t=None):
    from datetime import UTC, datetime
    return {"current_path": path, "user": user, "sim_ts": t or datetime(2026, 11, 8, 2, 0, 30, tzinfo=UTC)}


def test_attack_outputs():
    from datetime import UTC, datetime, timedelta
    t0 = datetime(2026, 11, 8, 2, 0, 0, tzinfo=UTC)
    assert is_attack_output(_c("/Q3/Budget.xlsx.dwtalocked"), {}, OUT)
    assert is_attack_output(_c("/Q3/README-DWTA-TEST.txt"), {}, OUT)
    assert not is_attack_output(_c("/Q3/Q3-Report.pdf"), {}, OUT)
    deleted = {"/Q3/a.docx": ("svc-backup", t0)}
    assert is_attack_output(_c("/Q3/a.docx.zzz"), deleted, OUT)                                   # same user, 30 s
    assert not is_attack_output(_c("/Q3/a.docx.zzz", user="jdoe"), deleted, OUT)                  # other user
    assert not is_attack_output(_c("/Q3/a.docx.zzz", t=t0 + timedelta(minutes=5)), deleted, OUT)  # too late


def test_tie_break_from_config():
    from datetime import UTC, datetime

    from dwta_incident.engine import Item, sort_items
    t = lambda h: datetime(2026, 11, 2, h, tzinfo=UTC)  # noqa: E731
    items = [Item("a", "file", 30, "low", t(9)), Item("b", "file", 230, "high", t(10)), Item("c", "file", 30, "low", t(8))]
    assert [i.item_key for i in sort_items(items, RANK["tie_break"])] == ["b", "c", "a"]
    assert [i.item_key for i in sort_items(items, ["sim_ts:desc"])] == ["b", "a", "c"]


def test_av_rescan_verdicts():
    from dwta_incident.av import AvVerdict, NullScanner, apply_verdict
    reasons = []
    assert NullScanner().scan("finance", "/x").verdict == "not_scanned"
    assert apply_verdict(130, reasons, AvVerdict("not_scanned", engine="none"), RANK) == 130 and reasons == []
    assert apply_verdict(130, reasons, AvVerdict("clean", engine="clamav"), RANK) == 130 and reasons == []
    assert apply_verdict(130, reasons, AvVerdict("detected", "DwTA.TestFamily", "clamav", "27450"), RANK) == 230
    assert reasons[0]["signal"] == "S-AV" and reasons[0]["evidence"]["signature"] == "DwTA.TestFamily"
    assert level_for(230, RANK["levels"]) == "high"
