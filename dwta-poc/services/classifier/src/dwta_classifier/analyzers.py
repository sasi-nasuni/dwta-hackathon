"""Analyzers (spec §5.5.2/3): "what is inside it?". They run on the bytes of the single content pass."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("classifier.analyzers")


@dataclass(frozen=True)
class Signal:
    id: str
    severity: str
    detail: str
    analyzer: str
    weight: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OletoolsAnalyzer:
    name = "oletools"

    def applies_to(self, type_class: str, label: str) -> bool:
        return type_class in ("office_doc", "office_macro")

    def analyze(self, data: bytes, filename: str) -> list[Signal]:
        from oletools.olevba import VBA_Parser

        out: list[Signal] = []
        try:
            vp = VBA_Parser(filename, data=data)
            # olevba also parses plain text as VBA source; only real containers count
            if vp.type == "Text" or not vp.detect_vba_macros():
                return out
            out.append(Signal("macro.present", "low", "VBA macros present", self.name))
            seen = set()
            for kind, keyword, _desc in vp.analyze_macros():
                if kind == "AutoExec" and keyword not in seen:
                    seen.add(keyword)
                    out.append(Signal("macro.autoexec", "medium", f"auto-exec trigger: {keyword}", self.name))
                elif kind == "Suspicious" and keyword not in seen:
                    seen.add(keyword)
                    out.append(Signal("macro.suspicious", "low", f"suspicious keyword: {keyword}", self.name))
            vp.close()
        except Exception as e:  # malformed documents must not stop the pipeline
            log.debug("olevba failed on %s: %s", filename, e)
        return out


class YaraAnalyzer:
    name = "yara-x"

    def __init__(self, rules_dir: Path) -> None:
        import yara_x

        sources = "\n".join(p.read_text() for p in sorted(rules_dir.glob("*.yar")))
        self.rules = yara_x.compile(sources)

    def applies_to(self, type_class: str, label: str) -> bool:
        return True

    def analyze(self, data: bytes, filename: str) -> list[Signal]:
        out = []
        for m in self.rules.scan(data).matching_rules:
            meta = dict(m.metadata)
            out.append(Signal(f"yara.{m.identifier}", str(meta.get("severity", "medium")),
                              str(meta.get("description", m.identifier)), self.name, int(meta.get("weight", 10))))
        return out
