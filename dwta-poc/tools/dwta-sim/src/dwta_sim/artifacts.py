"""Approved safe artifacts (spec §5.3.6), generated from code: no binaries are downloaded or stored.

* ``benign_pe``: a structurally valid PE32+ image whose only code is ``ret`` (0xC3). It does nothing.
* ``eicar``: the industry-standard antivirus test string (harmless text).
"""

from __future__ import annotations

import hashlib
import struct


def benign_pe(tag: bytes = b"DwTA benign test executable", size: int = 245760) -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<HBBIIIII", opt, 0, 0x20B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)  # magic, linker, sizes, entry, base of code
    struct.pack_into("<Q", opt, 24, 0x140000000)            # image base
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)          # section / file alignment
    struct.pack_into("<HH", opt, 40, 6, 0)                   # OS version
    struct.pack_into("<HH", opt, 48, 6, 0)                   # subsystem version
    struct.pack_into("<II", opt, 56, 0x2000, 0x200)          # size of image, size of headers
    struct.pack_into("<H", opt, 68, 3)                       # subsystem: console
    struct.pack_into("<I", opt, 108, 16)                     # number of data directories
    section = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    header = bytes(dos) + coff + bytes(opt) + section
    header += b"\0" * (0x200 - len(header))
    text = b"\xc3" + tag + b"\0"
    text += b"\0" * (0x200 - len(text))
    body = header + text
    # deterministic, low-entropy padding up to the requested size
    pad = (hashlib.sha256(tag).hexdigest().encode() * (size // 64 + 1))[: max(0, size - len(body))]
    return body + pad


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

APPROVED: dict[str, bytes] = {}


def get(name: str) -> bytes:
    """Only names in this registry may be planted (SIM-07)."""
    if not APPROVED:
        APPROVED.update({"benign_pe": benign_pe(), "eicar": EICAR})
    if name not in APPROVED:
        raise KeyError(f"artifact {name!r} is not on the approved list: {sorted(APPROVED)}")
    return APPROVED[name]


def sha256_of(name: str) -> str:
    return hashlib.sha256(get(name)).hexdigest()
