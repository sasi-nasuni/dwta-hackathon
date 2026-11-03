"""Contract tests (spec §6): every artifact the lab produced validates against its JSON Schema in specs/schemas.

Runs against the default instance's real output; skipped when that instance has no data yet.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from dwta_core.config import specs_dir
from dwta_core.fileio import read_jsonl
from dwta_core.journal import JournalReader

LAB = Path(__file__).resolve().parents[2] / "lab" / "dwta1"
SCHEMAS = specs_dir() / "schemas"


def _validator(name: str) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(json.loads((SCHEMAS / f"{name}.schema.json").read_text()))


def _require(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"no lab output at {path}; run `make demo` first")
    return path


def test_schemas_are_valid_json_schema():
    for p in SCHEMAS.glob("*.schema.json"):
        jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text()))


def test_fs_events():
    v = _validator("fs_event.v1")
    events = [e for _, e in JournalReader(_require(LAB / "run" / "journal")).read(limit=10**9)]
    assert events
    for e in events:
        v.validate(e)


def test_groundtruth():
    v = _validator("groundtruth.v1")
    for f in _require(LAB / "run" / "runs").glob("*/groundtruth.jsonl"):
        for row in read_jsonl(f):
            v.validate(row)


def test_incidents_review_lists_and_manifests():
    incidents = _require(LAB / "incidents")
    for f in (incidents / "processed").glob("*.json"):
        _validator("incident.v1").validate(json.loads(f.read_text()))
    for f in (LAB / "run" / "incidents").glob("*/review-list.json"):
        _validator("review_list.v1").validate(json.loads(f.read_text()))
    for f in (LAB / "run" / "incidents").glob("*/restore-exclusions.json"):
        _validator("restore_exclusions.v1").validate(json.loads(f.read_text()))
