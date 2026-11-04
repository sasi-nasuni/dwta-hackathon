"""SMB operations an actor performs, as transport-agnostic ``Op`` records.

The action code builds a list of ``Op`` (put/get/rename/delete/mkdir) with ``SmbSession`` and calls ``run``;
the actor's transport (docker container, Linux VM or Windows VM - see ``transport.py``) renders and executes them.
All traffic originates from the actor's own client so the Edge records a distinct source IP per user (SMBC-03/04).
"""

from __future__ import annotations

import time
from dataclasses import dataclass


class SmbError(RuntimeError):
    pass


@dataclass(frozen=True)
class Op:
    kind: str            # mkdir | put | get | rename | delete
    a: str = ""          # remote (share-relative) path; for rename, the source
    b: str = ""          # local file for put/get; for rename, the destination (share-relative)
    replace: bool = False


def rel(path: str) -> str:
    """Share-relative form smbclient/PowerShell expect (no leading slash)."""
    return path.lstrip("/")


class SmbSession:
    """One actor+identity session. Ops are built with the static helpers and run through the actor's transport."""

    def __init__(self, instance, actor: str, identity: str, netbios: str):
        self.instance = instance
        self.actor = actor
        self.identity = identity
        self.netbios = netbios
        from .transport import make_transport
        self._transport = make_transport(instance, actor, identity, netbios)

    def run(self, share: str, ops: list[Op], check: bool = True) -> str:
        return self._transport.run(share, list(ops), check=check)

    # Op constructors (paths are share-relative, e.g. "/Q3/Q3-Report.pdf"; local paths are host staging/corpus files)
    @staticmethod
    def put(local: str, remote: str) -> Op:
        return Op("put", remote, local)

    @staticmethod
    def get(remote: str, local: str) -> Op:
        return Op("get", remote, local)

    @staticmethod
    def rename(src: str, dst: str, replace: bool = False) -> Op:
        return Op("rename", src, dst, replace)

    @staticmethod
    def delete(remote: str) -> Op:
        return Op("delete", remote)

    @staticmethod
    def mkdir(remote: str) -> Op:
        return Op("mkdir", remote)


def wait_settle(seconds: float = 0.3) -> None:
    time.sleep(seconds)
