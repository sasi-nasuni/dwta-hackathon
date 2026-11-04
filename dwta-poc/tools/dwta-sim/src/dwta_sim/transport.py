"""SMB transports: how an actor's file operations actually reach the Edge.

Each actor runs its SMB operations from its own client so the Edge records a distinct source IP per user
(SMBC-03/04). Three transports share one interface:

* ``DockerTransport``   - exec ``smbclient`` in the actor's local client container (the original lab path).
* ``LinuxVmTransport``  - run ``smbclient`` on a Linux VM over SSH (real per-user IP).
* ``WindowsVmTransport``- drive an SMB mapping with PowerShell on a Windows VM over SSH (real per-user IP).

The VM transports stage the bytes a ``put`` needs onto the VM first and copy a ``get`` result back, so the
encrypt read/transform/write-back loop works unchanged. File content never leaves the actor's own client for
anything except this staging hop.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
from dataclasses import dataclass

from .smb import Op, SmbError, rel

# identity (simulator role) -> env vars holding the Edge/AD account it logs in as
IDENTITY_USERVAR = {"admin": "SMB_USER_ADMIN", "jdoe": "SMB_USER_JDOE",
                    "asmith": "SMB_USER_ASMITH", "svc-backup": "SMB_USER_SVC_BACKUP"}
IDENTITY_PWVAR = {"admin": "SMB_PW_ITADMIN", "jdoe": "SMB_PW_JDOE",
                  "asmith": "SMB_PW_ASMITH", "svc-backup": "SMB_PW_SVC_BACKUP"}


@dataclass
class Creds:
    user: str
    password: str
    domain: str | None


def creds_for(env: dict[str, str], identity: str) -> Creds:
    try:
        user = env[IDENTITY_USERVAR[identity]]
        pw = env[IDENTITY_PWVAR[identity]]
    except KeyError as e:
        raise SmbError(f"no credentials in .env for identity {identity!r} ({e})") from None
    return Creds(user, pw, env.get("SMB_DOMAIN") or None)


def _smbclient_cmd(op: Op) -> str:
    """Render one Op as an smbclient batch command (local paths already mapped to the client's filesystem)."""
    if op.kind == "mkdir":
        return f"mkdir {_q(rel(op.a))}"
    if op.kind == "put":
        return f"put {_q(op.b)} {_q(rel(op.a))}"
    if op.kind == "get":
        return f"get {_q(rel(op.a))} {_q(op.b)}"
    if op.kind == "rename":
        return f"rename {_q(rel(op.a))} {_q(rel(op.b))}" + (" -f" if op.replace else "")
    if op.kind == "delete":
        return f"del {_q(rel(op.a))}"
    raise SmbError(f"unknown op {op.kind}")


def _q(path: str) -> str:
    return '"' + path.replace('"', "") + '"'


def _smbclient_failures(out: str) -> list[str]:
    return [ln for ln in out.splitlines()
            if "NT_STATUS_" in ln and "NT_STATUS_OBJECT_NAME_COLLISION" not in ln]


# ---------------------------------------------------------------------------- docker (original behaviour)
class DockerTransport:
    def __init__(self, instance, actor: str, identity: str, netbios: str):
        self.instance, self.actor, self.identity, self.netbios = instance, actor, identity, netbios
        self._cid: str | None = None

    def _container(self) -> str:
        if self._cid is None:
            out = self.instance.compose("ps", "-q", self.actor, capture=True).stdout.decode().strip()
            if not out:
                raise SmbError(f"{self.actor} is not running; start the lab first")
            self._cid = out.splitlines()[0]
        return self._cid

    def _map(self, local: str) -> str:
        """Map a host path (staging or corpus) to the matching container mount."""
        staging = str(self.instance.staging)
        corpus = str(self.instance.corpus_root)
        if local.startswith(staging):
            return "/staging" + local[len(staging):]
        if local.startswith(corpus):
            return "/corpus" + local[len(corpus):]
        return local

    def run(self, share: str, ops: list[Op], check: bool = True) -> str:
        mapped = [Op(o.kind, o.a, self._map(o.b) if o.kind in ("put", "get") else o.b, o.replace) for o in ops]
        script = "; ".join(_smbclient_cmd(o) for o in mapped)
        argv = ["docker", "exec", self._container(), "smbclient", f"//{self.instance.smb_host}/{share}",
                "-A", f"/run/secrets/smb-{self.identity}", "-n", self.netbios, "-m", "SMB3",
                "--option=client min protocol=SMB2", "-c", script]
        p = subprocess.run(argv, capture_output=True, text=True)
        out = p.stdout + p.stderr
        if check and (p.returncode != 0 or _smbclient_failures(out)):
            raise SmbError(f"smbclient failed ({self.actor} as {self.identity} on {share}): "
                           f"{_smbclient_failures(out) or out.strip()[:400]}")
        return out


# ---------------------------------------------------------------------------- shared SSH helpers for VM transports
def _ssh_base(host: str, ssh_user: str, password: str | None) -> tuple[list[str], dict[str, str]]:
    env = dict(os.environ)
    opts = ["-o", "BatchMode=" + ("no" if password else "yes"), "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]
    if password:
        env["SSHPASS"] = password
        return ["sshpass", "-e", "ssh", *opts, f"{ssh_user}@{host}"], env
    return ["ssh", *opts, f"{ssh_user}@{host}"], env


class _VmBase:
    """Common VM plumbing: SSH (with timeout), an absolute per-VM staging root, and batched host<->VM transfers.

    All of an actor's staged/corpus files move in a single ``tar`` stream per direction, so a burst of N files
    costs two SSH round trips, not 2*N. SMB file operations themselves run in one session on the VM.
    """

    SSH_TIMEOUT = 300  # generous ceiling for a whole-batch tar stream; a hung SSH fails instead of blocking forever

    def __init__(self, instance, actor, identity, netbios, host, ssh_user, password):
        self.instance, self.actor, self.identity, self.netbios = instance, actor, identity, netbios
        self.host, self.ssh_user, self.password = host, ssh_user, password
        self.creds = creds_for(instance.env(), identity)
        self._lock = threading.Lock()
        self._root: str | None = None

    def _ssh(self, remote_cmd: str, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        argv, env = _ssh_base(self.host, self.ssh_user, self.password)
        try:
            p = subprocess.run([*argv, remote_cmd], input=input_bytes, capture_output=True, env=env,
                               timeout=self.SSH_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise SmbError(f"ssh {self.host} timed out after {self.SSH_TIMEOUT}s ({self.actor})") from None
        if check and p.returncode != 0:
            raise SmbError(f"ssh {self.host} failed ({self.actor}): {p.stderr.decode(errors='replace')[:300]}")
        return p

    def _rel_local(self, host_path: str) -> str:
        """Path of a staging/corpus file relative to its host root (so it maps under the VM staging dir)."""
        staging, corpus = str(self.instance.staging), str(self.instance.corpus_root)
        if host_path.startswith(staging):
            return "staging" + host_path[len(staging):]
        if host_path.startswith(corpus):
            return "corpus" + host_path[len(corpus):]
        return "staging/" + os.path.basename(host_path)

    # -- absolute VM staging root (resolved once) --
    def root(self) -> str:
        if self._root is None:
            self._root = self._resolve_root()
        return self._root

    def _resolve_root(self) -> str:
        raise NotImplementedError

    # -- batched transfers via tar --
    def _push_batch(self, host_paths: list[str]) -> dict[str, str]:
        """Tar the host files and extract them under the VM root; returns {host_path: posix rel}."""
        import io
        import tarfile
        rels: dict[str, str] = {}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for hp in host_paths:
                if hp in rels:
                    continue
                rel = self._rel_local(hp)
                rels[hp] = rel
                tf.add(hp, arcname=rel)
        if rels:
            self._ssh(self._extract_cmd(), input_bytes=buf.getvalue())
        return rels

    def _pull_batch(self, items: list[tuple[str, str]]) -> None:
        """Tar the given VM rel paths and extract them to their host paths. items: (posix rel, host_path)."""
        import io
        import tarfile
        if not items:
            return
        data = self._ssh(self._create_cmd([r for r, _ in items])).stdout
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for rel, hp in items:
                src = tf.extractfile(tf.getmember(rel))
                os.makedirs(os.path.dirname(hp), exist_ok=True)
                with open(hp, "wb") as fh:
                    fh.write(src.read())

    def _extract_cmd(self) -> str:
        raise NotImplementedError

    def _create_cmd(self, rels: list[str]) -> str:
        raise NotImplementedError


# ---------------------------------------------------------------------------- Linux VM (smbclient over SSH)
class LinuxVmTransport(_VmBase):
    def _resolve_root(self) -> str:
        home = self._ssh('printf %s "$HOME"').stdout.decode().strip()
        return f"{home}/dwta-sim"

    def _extract_cmd(self) -> str:
        root = shlex.quote(self.root())
        return f"mkdir -p {root} && tar -xf - -C {root}"

    def _create_cmd(self, rels: list[str]) -> str:
        root = shlex.quote(self.root())
        return f"tar -cf - -C {root} " + " ".join(shlex.quote(r) for r in rels)

    def _abs(self, rel: str) -> str:
        return f"{self.root()}/{rel}"

    def run(self, share: str, ops: list[Op], check: bool = True) -> str:
        rels = self._push_batch([o.b for o in ops if o.kind == "put"])
        mapped: list[Op] = []
        pulls: list[tuple[str, str]] = []
        for o in ops:
            if o.kind == "put":
                mapped.append(Op(o.kind, o.a, self._abs(rels[o.b])))
            elif o.kind == "get":
                rel = self._rel_local(o.b)
                mapped.append(Op(o.kind, o.a, self._abs(rel)))
                pulls.append((rel, o.b))
            else:
                mapped.append(o)
        script = "; ".join(_smbclient_cmd(o) for o in mapped)
        host = self.instance.smb_host
        auth = f"username = {self.creds.user}\npassword = {self.creds.password}\n"
        if self.creds.domain:
            auth += f"domain = {self.creds.domain}\n"
        getdirs = {self._abs(rel).rsplit("/", 1)[0] for rel, _ in pulls}
        mkdirs = ("mkdir -p " + " ".join(shlex.quote(d) for d in getdirs) + "; ") if getdirs else ""
        remote = (
            "set -e; umask 077; A=$(mktemp); cat > \"$A\" <<'AUTHEOF'\n" + auth + "AUTHEOF\n" + mkdirs
            + f"smbclient //{host}/{shlex.quote(share)} -A \"$A\" -m SMB3 "
            + "--option='client min protocol=SMB2' -c " + shlex.quote(script) + "; RC=$?; rm -f \"$A\"; exit $RC"
        )
        p = self._ssh(remote, check=False)
        out = (p.stdout + p.stderr).decode(errors="replace")
        if check and (p.returncode != 0 or _smbclient_failures(out)):
            raise SmbError(f"smbclient failed on {self.host} ({self.actor} as {self.identity} on {share}): "
                           f"{_smbclient_failures(out) or out.strip()[:400]}")
        self._pull_batch(pulls)
        return out


# ---------------------------------------------------------------------------- Windows VM (PowerShell over SSH)
class WindowsVmTransport(_VmBase):
    def _resolve_root(self) -> str:
        out = self._ssh('powershell -NoProfile -Command "[Console]::Out.Write($env:USERPROFILE)"').stdout
        return out.decode(errors="replace").strip() + "\\dwta-sim"

    def _extract_cmd(self) -> str:
        root = self.root()
        # sshd already runs the command via cmd.exe; tar.exe (bsdtar, Windows 10 1809+) creates dirs on extract.
        return f'mkdir "{root}" 2>nul & tar -xf - -C "{root}"'

    def _create_cmd(self, rels: list[str]) -> str:
        return f'tar -cf - -C "{self.root()}" ' + " ".join(rels)

    def _abs(self, rel: str) -> str:
        return self.root() + "\\" + rel.replace("/", "\\")

    @staticmethod
    def _unc_cmd(op: Op, unc: str, abspath) -> str:
        """Render one Op as PowerShell; op.b for put/get is an absolute VM path."""
        def u(path: str) -> str:
            return unc + "\\" + rel(path).replace("/", "\\")
        if op.kind == "mkdir":
            return f"New-Item -ItemType Directory -Force -Path '{u(op.a)}' | Out-Null"
        if op.kind == "put":
            return f"Copy-Item -LiteralPath '{op.b}' -Destination '{u(op.a)}' -Force"
        if op.kind == "get":
            return f"Copy-Item -LiteralPath '{u(op.a)}' -Destination '{op.b}' -Force"
        if op.kind == "rename":
            return f"Move-Item -LiteralPath '{u(op.a)}' -Destination '{u(op.b)}' -Force"
        if op.kind == "delete":
            return f"Remove-Item -LiteralPath '{u(op.a)}' -Force"
        raise SmbError(f"unknown op {op.kind}")

    def _ps(self, script: str, check: bool = True) -> subprocess.CompletedProcess:
        # Pipe the script over stdin so credentials never appear in the VM process list.
        return self._ssh("powershell -NoProfile -NonInteractive -Command -", input_bytes=script.encode(), check=check)

    def run(self, share: str, ops: list[Op], check: bool = True) -> str:
        unc = f"\\\\{self.instance.smb_host}\\{share}"
        with self._lock:  # one SMB session to this server at a time (Windows forbids concurrent conflicting ones)
            rels = self._push_batch([o.b for o in ops if o.kind == "put"])
            mapped: list[Op] = []
            pulls: list[tuple[str, str]] = []
            getdirs: set[str] = set()
            for o in ops:
                if o.kind == "put":
                    mapped.append(Op(o.kind, o.a, self._abs(rels[o.b])))
                elif o.kind == "get":
                    rel_ = self._rel_local(o.b)
                    mapped.append(Op(o.kind, o.a, self._abs(rel_)))
                    pulls.append((rel_, o.b))
                    getdirs.add(self._abs(rel_).rsplit("\\", 1)[0])
                else:
                    mapped.append(o)
            user = (self.creds.domain + "\\" if self.creds.domain else "") + self.creds.user
            mkdirs = "".join(f"New-Item -ItemType Directory -Force -Path '{d}' | Out-Null\n" for d in getdirs)
            body = "\n".join(self._unc_cmd(o, unc, self._abs) for o in mapped)
            connect = f"cmd /c 'net use {unc} /user:{user} \"{self.creds.password}\"' | Out-Null\n"
            # The session is always torn down in the Python finally (a PowerShell try/finally misparses over SSH stdin).
            script = "$ErrorActionPreference='Stop'\n" + mkdirs + connect + body + "\n"
            try:
                p = self._ps(script, check=False)
                out = (p.stdout + p.stderr).decode(errors="replace")
                if check and p.returncode != 0:
                    raise SmbError(f"powershell SMB failed on {self.host} ({self.actor} as {self.identity} "
                                   f"on {share}): {out.strip()[:500]}")
                self._pull_batch(pulls)
                return out
            finally:
                self._ps(f"cmd /c 'net use {unc} /delete /y' | Out-Null", check=False)


def make_transport(instance, actor: str, identity: str, netbios: str):
    """Pick the transport for an actor from the instance's VM configuration (falls back to the docker client)."""
    env = instance.env()
    if env.get("VM_MODE", "").lower() in ("on", "1", "true", "yes"):
        key = actor.upper().replace("-", "_")
        host = env.get(f"VM_{key}_HOST")
        if host:
            os_kind = env.get(f"VM_{key}_OS", "linux").lower()
            ssh_user = env.get(f"VM_{key}_SSH_USER") or env.get("VM_SSH_USER", "automation")
            password = None
            if (env.get(f"VM_{key}_AUTH") or env.get("VM_AUTH", "key")).lower() == "password":
                password = env.get(f"VM_{key}_SSH_PASS") or env.get("VM_SSH_PASS")
            cls = WindowsVmTransport if os_kind.startswith("win") else LinuxVmTransport
            return cls(instance, actor, identity, netbios, host, ssh_user, password)
    return DockerTransport(instance, actor, identity, netbios)
