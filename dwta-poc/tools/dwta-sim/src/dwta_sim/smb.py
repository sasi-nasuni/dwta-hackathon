"""Runs smbclient inside an actor's client container (SMBC-03/04). All SMB traffic originates there."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from .lab import Instance


class SmbError(RuntimeError):
    pass


def _quote(path: str) -> str:
    return '"' + path.replace('"', "") + '"'


@dataclass
class SmbSession:
    instance: Instance
    actor: str            # client container service name, e.g. "client-attack"
    identity: str         # credentials to log in with (may differ from the actor's own: U8)
    netbios: str          # always the actor machine's name
    _container: str | None = None

    def container(self) -> str:
        if self._container is None:
            out = self.instance.compose("ps", "-q", self.actor, capture=True).stdout.decode().strip()
            if not out:
                raise SmbError(f"{self.actor} is not running; start the lab with `dwta-lab up`")
            self._container = out.splitlines()[0]
        return self._container

    def run(self, share: str, commands: list[str], check: bool = True) -> str:
        """Runs a batch of smbclient commands in one session. Returns combined output."""
        script = "; ".join(commands)
        argv = ["docker", "exec", self.container(), "smbclient", f"//samba/{share}",
                "-A", f"/run/secrets/smb-{self.identity}", "-n", self.netbios, "-m", "SMB3",
                "--option=client min protocol=SMB2", "-c", script]
        p = subprocess.run(argv, capture_output=True, text=True)
        out = p.stdout + p.stderr
        failed = [ln for ln in out.splitlines() if "NT_STATUS_" in ln and "NT_STATUS_OBJECT_NAME_COLLISION" not in ln]
        if check and (p.returncode != 0 or failed):
            raise SmbError(f"smbclient failed ({self.actor} as {self.identity} on {share}): {failed or out.strip()[:400]}")
        return out

    # convenience wrappers (paths are share-relative, e.g. "/Q3/Q3-Report.pdf"; local paths are in the container)
    @staticmethod
    def put(local: str, remote: str) -> str:
        return f"put {_quote(local)} {_quote(remote.lstrip('/'))}"

    @staticmethod
    def get(remote: str, local: str) -> str:
        return f"get {_quote(remote.lstrip('/'))} {_quote(local)}"

    @staticmethod
    def rename(src: str, dst: str, replace: bool = False) -> str:
        return f"rename {_quote(src.lstrip('/'))} {_quote(dst.lstrip('/'))}" + (" -f" if replace else "")

    @staticmethod
    def delete(remote: str) -> str:
        return f"del {_quote(remote.lstrip('/'))}"

    @staticmethod
    def mkdir(remote: str) -> str:
        return f"mkdir {_quote(remote.lstrip('/'))}"

    @staticmethod
    def copy_dir(local_dir: str, remote_dir: str) -> list[str]:
        """Recursive upload of a container-local directory (SMBC-05: mput with recurse)."""
        return ["recurse ON", "prompt OFF", f"lcd {_quote(local_dir)}", cd(remote_dir), "mput *"]

    def list_shares(self) -> str:
        """SMBC-05: list the shares visible to this identity."""
        argv = ["docker", "exec", self.container(), "smbclient", "-L", "//samba", "-A",
                f"/run/secrets/smb-{self.identity}", "-n", self.netbios, "-m", "SMB3",
                "--option=client min protocol=SMB2", "-g"]
        p = subprocess.run(argv, capture_output=True, text=True)
        if p.returncode != 0:
            raise SmbError(p.stdout + p.stderr)
        return p.stdout


def cd(remote_dir: str) -> str:
    return f"cd {_quote(remote_dir.lstrip('/') or '/')}"


def wait_settle(seconds: float = 0.3) -> None:
    time.sleep(seconds)
