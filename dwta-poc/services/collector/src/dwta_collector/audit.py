"""Parses Samba ``vfs_full_audit`` lines (format pinned by spike V-01).

Example line (debug header, then ``full_audit:prefix = %T|%u|%I|%m|%S|%d``, op, result, args)::

    [2026/11/03 09:03:48.817911,  1]   2026/11/03 09:03:48|jdoe|10.250.1.21|ws-jdoe01|finance|133|create_file|ok|0x12019f|file|overwrite_if|/srv/shares/finance/Q3/x.tmp
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

_HEADER = re.compile(r"^\[(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d+),\s*\d+\]\s+(.*)$")


@dataclass(frozen=True)
class AuditRecord:
    ts: datetime          # microsecond time from the debug header (container clock = UTC)
    user: str
    client_ip: str
    client_name: str      # NetBIOS name, upper-cased
    share: str
    pid: str
    op: str
    ok: bool
    args: tuple[str, ...]
    offset: int           # byte offset of the line in audit.log (traceability)


def parse_line(line: str, offset: int = 0) -> AuditRecord | None:
    m = _HEADER.match(line.rstrip("\n"))
    if not m:
        return None
    parts = m[2].split("|")
    if len(parts) < 8:
        return None
    _t, user, ip, machine, share, pid, op, result, *args = parts
    ts = datetime.strptime(m[1], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=UTC)
    return AuditRecord(ts, user, ip, machine.upper(), share, pid, op, result == "ok", tuple(args), offset)
