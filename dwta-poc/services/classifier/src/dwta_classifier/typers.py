"""Typers (spec §5.5.2/3): "what is this file?" from head/tail bytes. Rules typer + optional Magika typer."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .content import ContentFacts


@dataclass(frozen=True)
class TypeVerdict:
    type_class: str
    label: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)


def _zip_names(tail: bytes) -> list[str] | None:
    """File names from the ZIP central directory, if it fits in the tail window (it always does for EOCD)."""
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or len(tail) - eocd < 22:
        return None
    cd_size, cd_off = struct.unpack_from("<II", tail, eocd + 12)
    start = eocd - cd_size
    if start < 0:
        return None
    names, i = [], start
    while i + 46 <= eocd and tail[i:i + 4] == b"PK\x01\x02":
        n_len, x_len, c_len = struct.unpack_from("<HHH", tail, i + 28)
        names.append(tail[i + 46:i + 46 + n_len].decode("utf-8", "replace"))
        i += 46 + n_len + x_len + c_len
    return names


class RulesTyper:
    name = "rules"
    version = "1.0"

    def __init__(self, magic_cfg: dict[str, Any]) -> None:
        self.sigs = [dict(s, magic=bytes.fromhex(s["hex"])) for s in magic_cfg["signature"]]
        self.script_markers = [m.lower().encode() for m in magic_cfg["script_markers"]]
        self.eicar = magic_cfg["eicar"].encode()
        self.text_sample = magic_cfg.get("text_sample_bytes", 4096)

    def type(self, f: ContentFacts) -> TypeVerdict:
        head = f.head
        if f.size == 0:
            return TypeVerdict("unknown", "empty", 1.0)
        if head.startswith(self.eicar):
            return TypeVerdict("test_signature", "eicar", 1.0)
        for s in self.sigs:
            window = head[: s.get("search_bytes", len(s["magic"]))]
            hit = head.startswith(s["magic"]) if "search_bytes" not in s else s["magic"] in window
            if hit:
                return getattr(self, f"_check_{s['check']}")(s, f) if s.get("check") else TypeVerdict(
                    s["type_class"], s["label"], 1.0, {"magic": s["hex"]})
        sample = head[: self.text_sample]
        if b"\x00" in sample or sum(c < 9 or 13 < c < 32 for c in sample) > len(sample) * 0.05:
            return TypeVerdict("unknown", "binary", 0.5)
        low = sample.lstrip().lower()
        if any(low.startswith(m) for m in self.script_markers):
            return TypeVerdict("script", "script", 0.9)
        return TypeVerdict("text", "text", 0.9)

    # structural refinements ------------------------------------------------------------
    def _check_pe_header(self, s: dict, f: ContentFacts) -> TypeVerdict:
        head = f.head
        if len(head) >= 0x40:
            off = struct.unpack_from("<I", head, 0x3C)[0]
            if off + 4 <= len(head) and head[off:off + 4] == b"PE\0\0":
                return TypeVerdict("pe_binary", "pe", 1.0, {"e_lfanew": off})
        return TypeVerdict("pe_binary", "mz_only", 0.7, {"magic": "4d5a"})

    def _check_zip(self, s: dict, f: ContentFacts) -> TypeVerdict:
        names = _zip_names(f.tail) or []
        if "[Content_Types].xml" in names:
            kind = next((k for p, k in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")) if any(n.startswith(p) for n in names)), "ooxml")
            macro = any(n.lower().endswith("vbaproject.bin") for n in names)
            return TypeVerdict("office_macro" if macro else "office_doc", kind, 1.0, {"ooxml": kind, "vba_project": macro})
        return TypeVerdict("archive", "zip", 1.0, {"entries": len(names)})

    def _check_ole2(self, s: dict, f: ContentFacts) -> TypeVerdict:
        # macro presence in legacy OLE files is decided by the oletools analyzer (same content pass)
        return TypeVerdict("office_doc", "ole2", 0.9)


class MagikaTyper:
    """AI typer. Any failure leaves the rules path untouched (CLS-06)."""

    name = "magika"

    def __init__(self, label_map: dict[str, str]) -> None:
        from magika import Magika  # imported lazily: optional dependency

        self.m = Magika()
        self.version = f"magika-{__import__('magika').__version__}"
        self.label_map = label_map

    def type(self, f: ContentFacts) -> TypeVerdict:
        data = f.content if f.content is not None else f.head + f.tail
        res = self.m.identify_bytes(data)
        label = res.output.label
        return TypeVerdict(self.label_map.get(label, "unknown"), label, float(res.score))
