"""Deterministic benign corpus packs (spec §5.3.5): same profile + seed -> byte-identical files and manifest.

A pack is ``lab/corpus/<profile>-<seed>/`` with ``files/<share>/<path>`` and ``manifest.json``.
Every file has correct magic bytes so the classifier sees realistic data.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
import struct
import zipfile
import zlib
from pathlib import Path

from dwta_core.fileio import atomic_write_json

from .artifacts import benign_pe

ZIP_DATE = (2026, 1, 1, 0, 0, 0)
WORDS = ("revenue forecast margin budget quarter region invoice ledger payroll audit vendor contract "
         "accrual capex opex headcount variance target pipeline renewal churn").split()


def _text(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def make_pdf(rng: random.Random) -> bytes:
    body = _text(rng, rng.randint(80, 400)).encode()
    stream = b"BT /F1 12 Tf 72 720 Td (" + body[:200] + b") Tj ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    out += b"% " + body + b"\n"  # padding keeps sizes realistic
    return bytes(out)


def make_docx(rng: random.Random) -> bytes:
    paras = "".join(f"<w:p><w:r><w:t>{_text(rng, 30)}</w:t></w:r></w:p>" for _ in range(rng.randint(5, 40)))
    return _zip({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                               b'<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" '
                               b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                              f"<w:body>{paras}</w:body></w:document>").encode(),
    })


def make_xlsx(rng: random.Random) -> bytes:
    rows = "".join(f'<row r="{r}"><c r="A{r}"><v>{rng.randint(1, 99999)}</v></c></row>' for r in range(1, rng.randint(20, 200)))
    return _zip({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                               b'<Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" '
                               b'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
        "_rels/.rels": b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": b'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Q" sheetId="1"/></sheets></workbook>',
        "xl/worksheets/sheet1.xml": ('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                     f"<sheetData>{rows}</sheetData></worksheet>").encode(),
    })


def make_csv(rng: random.Random) -> bytes:
    lines = ["date,account,amount,region"]
    lines += [f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d},{rng.choice(WORDS)},{rng.randint(10, 99999)}.{rng.randint(0, 99):02d},"
              f"{rng.choice(['EMEA', 'APAC', 'AMER'])}" for _ in range(rng.randint(50, 600))]
    return ("\n".join(lines) + "\n").encode()


def make_txt(rng: random.Random) -> bytes:
    return ("\n".join(_text(rng, 15) for _ in range(rng.randint(10, 120))) + "\n").encode()


def make_png(rng: random.Random) -> bytes:
    w, h = rng.randint(16, 64), rng.randint(16, 64)
    raw = b"".join(b"\0" + bytes(rng.randrange(256) for _ in range(w * 3)) for _ in range(h))

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def make_elf(rng: random.Random) -> bytes:
    hdr = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHI", 2, 0xB7, 1) + b"\0" * 40
    return hdr + _text(rng, 200).encode()


def make_exe(rng: random.Random) -> bytes:
    return benign_pe(tag=f"DwTA corpus tool {rng.randint(0, 10**9)}".encode(), size=rng.randint(20000, 90000))


def make_zip(rng: random.Random) -> bytes:
    return _zip({f"readme-{i}.txt": make_txt(rng) for i in range(rng.randint(1, 4))})


MAKERS = {"pdf": make_pdf, "docx": make_docx, "xlsx": make_xlsx, "csv": make_csv, "txt": make_txt,
          "png": make_png, "exe": make_exe, "elf": make_elf, "zip": make_zip}

PROFILES = {
    "default": {
        "finance": [(f"/Q{q}", kind, n) for q in range(1, 5)
                    for kind, n in (("pdf", 2), ("docx", 2), ("xlsx", 2), ("csv", 2), ("txt", 1), ("png", 1))],
        "software": [("/tools", "exe", 4), ("/tools", "elf", 3), ("/tools", "zip", 3)],
    },
}

NAMES = {"pdf": ["Report", "Statement", "Summary"], "docx": ["Plan", "Memo", "Minutes"], "xlsx": ["Budget", "Forecast", "Payroll"],
         "csv": ["Ledger", "Invoices"], "txt": ["Notes"], "png": ["Chart"], "exe": ["setup", "agent", "updater", "installer"],
         "elf": ["tool", "sync", "backup"], "zip": ["bundle", "docs", "archive"]}


def make_file(kind: str, rng: random.Random) -> bytes:
    return MAKERS[kind](rng)


def build(out_root: Path, profile: str = "default", seed: int = 42) -> Path:
    pack_id = f"{profile}-{seed}"
    pack = out_root / pack_id
    rng = random.Random(f"{profile}:{seed}")
    files = []
    for share, groups in PROFILES[profile].items():
        for folder, kind, n in groups:
            for i in range(n):
                stem = NAMES[kind][i % len(NAMES[kind])]
                ext = "bin" if kind == "elf" else kind
                prefix = f"{folder.strip('/')}-" if share == "finance" else ""
                name = f"{prefix}{stem}-{i + 1}.{ext}"
                data = make_file(kind, rng)
                rel = f"{folder}/{name}"
                dest = pack / "files" / share / rel.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                files.append({"share": share, "path": rel, "kind": kind, "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
    atomic_write_json(pack / "manifest.json", {"pack_id": pack_id, "profile": profile, "seed": seed, "files": files})
    return pack


def load_manifest(pack: Path) -> dict:
    return json.loads((pack / "manifest.json").read_text())


def verify(pack: Path) -> list[str]:
    bad = []
    for f in load_manifest(pack)["files"]:
        p = pack / "files" / f["share"] / f["path"].lstrip("/")
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != f["sha256"]:
            bad.append(f"{f['share']}{f['path']}")
    return bad
