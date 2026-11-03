import io
import zipfile
from pathlib import Path

import pytest
from dwta_classifier.analyzers import OletoolsAnalyzer, Signal, YaraAnalyzer
from dwta_classifier.content import ReadBudget, ReadCounter, SinglePass
from dwta_classifier.rules import evaluate, ext_mismatch, ext_of
from dwta_classifier.typers import RulesTyper
from dwta_core.config import load_config, specs_dir
from dwta_sim import artifacts, corpus

MAGIC = load_config("magic").data
EXT = load_config("ext_map").data["ext"]
RULES = load_config("rules").data


@pytest.fixture(scope="module")
def pack(tmp_path_factory):
    return corpus.build(tmp_path_factory.mktemp("corpus"), "default", 42)


def facts(tmp_path: Path, data: bytes, name="f.bin", cap=64 * 1024 * 1024, counter=None):
    p = tmp_path / name
    p.write_bytes(data)
    return SinglePass(ReadBudget(65536, 65557, cap), counter).run(p)


EXPECTED = {"pdf": "pdf", "docx": "office_doc", "xlsx": "office_doc", "csv": "text", "txt": "text", "png": "image",
            "exe": "pe_binary", "elf": "elf_binary", "zip": "archive"}


def test_rules_typer_on_corpus(pack, tmp_path):
    typer = RulesTyper(MAGIC)
    for f in corpus.load_manifest(pack)["files"]:
        data = (pack / "files" / f["share"] / f["path"].lstrip("/")).read_bytes()
        v = typer.type(facts(tmp_path, data))
        assert v.type_class == EXPECTED[f["kind"]], (f["path"], v)
        assert ext_mismatch(ext_of(f["path"]), v.type_class, EXT) in (False, None), f["path"]


def test_disguised_pe_is_caught(tmp_path):
    v = RulesTyper(MAGIC).type(facts(tmp_path, artifacts.get("benign_pe")))
    assert (v.type_class, v.label) == ("pe_binary", "pe")
    assert ext_mismatch("pdf", v.type_class, EXT) is True
    hits = evaluate(type_class="pe_binary", ext="pdf", mismatch=True, share_kind="document", signals=[],
                    prev_type=None, same_content=False, cfg=RULES)
    assert [(h.rule_id, h.severity) for h in hits] == [("R-W2", "high")]
    # same file on the software share: no alert (false-positive control)
    assert evaluate(type_class="pe_binary", ext="exe", mismatch=False, share_kind="software", signals=[],
                    prev_type=None, same_content=False, cfg=RULES) == []


def test_type_change_and_same_content():
    hits = evaluate(type_class="pe_binary", ext="pdf", mismatch=True, share_kind="document", signals=[],
                    prev_type="pdf", same_content=False, cfg=RULES)
    assert {h.rule_id for h in hits} == {"R-W2", "R-W6"}
    assert evaluate(type_class="pe_binary", ext="pdf", mismatch=True, share_kind="document", signals=[],
                    prev_type="pdf", same_content=True, cfg=RULES) == []


def test_eicar_and_yara(tmp_path):
    f = facts(tmp_path, artifacts.get("eicar"))
    assert RulesTyper(MAGIC).type(f).type_class == "test_signature"
    sigs = YaraAnalyzer(specs_dir() / "yara").analyze(f.content, "notes.txt")
    assert [s.id for s in sigs] == ["yara.EICAR_Test_File"]


def test_docm_macro_presence_from_tail(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\0" * 100)
    v = RulesTyper(MAGIC).type(facts(tmp_path, buf.getvalue()))
    assert v.type_class == "office_macro" and v.evidence["vba_project"]
    assert OletoolsAnalyzer().analyze(b"not an office file", "x.doc") == []


def test_read_budget_one_pass_and_cap(tmp_path):
    counter = ReadCounter()
    small = facts(tmp_path, b"A" * 200_000, "small.bin", cap=1_000_000, counter=counter)
    assert small.sha256 and small.analysis == "full" and counter.reads == [(str(tmp_path / "small.bin"), "pass", 200_000)]
    counter.reads.clear()
    big = facts(tmp_path, b"B" * 2_000_000, "big.bin", cap=1_000_000, counter=counter)
    assert big.sha256 is None and big.analysis == "partial"
    assert sum(n for _, _, n in counter.reads) <= 65536 + 65557


def test_signal_dict():
    assert Signal("a", "low", "d", "x").to_dict()["weight"] == 0
