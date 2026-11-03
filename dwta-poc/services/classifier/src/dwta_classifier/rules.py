"""Write-time rules (spec §5.5.5): extension mismatch and R-W1..R-W6. Pure functions, configured by TOML."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .analyzers import Signal


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str
    reasons: list[dict[str, Any]] = field(default_factory=list)


def ext_of(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name.strip(".") else None


def ext_mismatch(ext: str | None, type_class: str | None, ext_map: dict[str, list[str]]) -> bool | None:
    if not ext or ext not in ext_map or type_class is None:
        return None
    return type_class not in ext_map[ext]


def evaluate(*, type_class: str | None, ext: str | None, mismatch: bool | None, share_kind: str,
             signals: list[Signal], prev_type: str | None, same_content: bool, cfg: dict[str, Any]) -> list[RuleHit]:
    if same_content or type_class is None:
        return []
    rules, exec_classes = cfg["rule"], set(cfg["executable_classes"])
    hits: list[RuleHit] = []
    is_exec = type_class in exec_classes
    on_doc = share_kind == "document"
    base = {"type_class": type_class, "ext": ext, "share_kind": share_kind}
    if is_exec and on_doc:
        if mismatch:
            hits.append(RuleHit("R-W2", rules["R-W2"]["severity"], [{**base, "ext_mismatch": True}]))
        else:
            hits.append(RuleHit("R-W1", rules["R-W1"]["severity"], [base]))
    if on_doc and any(s.id == "macro.autoexec" for s in signals):
        hits.append(RuleHit("R-W3", rules["R-W3"]["severity"],
                            [{"signals": [s.detail for s in signals if s.id == "macro.autoexec"]}]))
    for s in signals:
        if s.id.startswith("yara."):
            hits.append(RuleHit(f"R-W4:{s.id[5:]}", s.severity, [{"rule": s.id[5:], "detail": s.detail}]))
    if is_exec and prev_type and prev_type not in exec_classes:
        hits.append(RuleHit("R-W6", rules["R-W6"]["severity"], [{"prev_type": prev_type, "type_class": type_class}]))
    return hits
