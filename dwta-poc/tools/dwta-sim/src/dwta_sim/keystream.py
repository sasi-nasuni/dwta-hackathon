"""Reversible "encryption" for the simulator: XOR with a SHA-256 counter-mode keystream (standard library only).

Produces high-entropy output like real ransomware, is deterministic for (key, path), and is its own inverse.
It is NOT meant to protect anything.
"""

from __future__ import annotations

import hashlib


def transform(data: bytes, key: bytes, nonce: str) -> bytes:
    n = nonce.encode()
    stream = b"".join(hashlib.sha256(key + n + i.to_bytes(8, "big")).digest() for i in range((len(data) + 31) // 32))
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream[: len(data)], "big")).to_bytes(len(data), "big") if data else b""
