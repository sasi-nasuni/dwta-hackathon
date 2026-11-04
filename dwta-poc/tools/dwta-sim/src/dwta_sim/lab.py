"""Lab instance on disk and in Docker: paths, generated .env, and docker compose calls. Standard library only."""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dwta_core.config import load_config, specs_dir


def repo_root() -> Path:
    env = os.environ.get("DWTA_REPO")
    if env:
        return Path(env)
    for parent in [Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents]:
        if (parent / "deploy" / "compose" / "docker-compose.yml").exists():
            return parent
    raise FileNotFoundError("repository root not found (deploy/compose/docker-compose.yml); set DWTA_REPO")


@dataclass(frozen=True)
class Instance:
    name: str
    root: Path  # lab/<name>

    @classmethod
    def get(cls, name: str) -> Instance:
        if name == "filer":
            from .filer import FilerInstance
            return FilerInstance("filer", repo_root() / "lab" / "filer")
        return cls(name, repo_root() / "lab" / name)

    # host-side folders (bind-mounted into the containers)
    @property
    def env_file(self) -> Path: return self.root / ".env"
    @property
    def data(self) -> Path: return self.root / "data"
    @property
    def logs(self) -> Path: return self.root / "logs"
    @property
    def run(self) -> Path: return self.root / "run"
    @property
    def staging(self) -> Path: return self.run / "staging"
    @property
    def feeds(self) -> Path: return self.root / "feeds"
    @property
    def incidents(self) -> Path: return self.root / "incidents"
    @property
    def secrets(self) -> Path: return self.root / "secrets"

    @property
    def corpus_root(self) -> Path: return repo_root() / "lab" / "corpus"

    def env(self) -> dict[str, str]:
        if not self.env_file.exists():
            raise FileNotFoundError(f"{self.env_file} missing; run `dwta-lab init --instance {self.name}`")
        out = {}
        for line in self.env_file.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out

    # ------------------------------------------------------------------ docker compose
    def compose_cmd(self, *args: str) -> list[str]:
        return ["docker", "compose", "-p", self.name, "--env-file", str(self.env_file),
                "-f", str(repo_root() / "deploy" / "compose" / "docker-compose.yml"), *args]

    def compose(self, *args: str, check: bool = True, capture: bool = False,
                input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(self.compose_cmd(*args), check=check, capture_output=capture, input=input_bytes)

    def exec(self, service: str, argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command in a running service container; returns captured output."""
        return self.compose("exec", "-T", service, *argv, check=check, capture=True)

    def container_ip(self, service: str) -> str:
        return self.env()[f"IP_{service.upper().replace('-', '_')}"]

    # ------------------------------------------------------------------ target hooks (lab = local Samba container)
    smb_host = "samba"

    def restore_actor(self) -> tuple[str, str]:
        """Actor+identity the Targeted Restore stand-in uses to put files back."""
        return ("client-admin", "admin")

    def append_clock(self, run_id: str, sim_now, wall) -> None:
        from dwta_core.simclock import append_entry
        append_entry(self.run / "simclock.jsonl", run_id, sim_now, wall)

    def measure_skew(self):
        from .context import measure_skew
        return measure_skew(self)

    def publish_feed(self, name: str, text: str) -> str:
        from dwta_core.fileio import atomic_write_text
        atomic_write_text(self.feeds / "inbox" / name, text)
        return f"feeds/inbox/{name}"

    def raise_incident(self, incident: dict) -> str:
        from dwta_core.fileio import atomic_write_json
        atomic_write_json(self.incidents / "inbox" / f"{incident['incident_id']}.json", incident)
        return f"incidents/inbox/{incident['incident_id']}.json"

    def snapshot(self) -> dict:
        return {"skipped": "the lab has no snapshots"}

    def safety_check(self) -> None:
        from .runner import safety_check
        safety_check(self)


# ---------------------------------------------------------------------- init helpers
def _port_in_use(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        if s.connect_ex(("127.0.0.1", port)) == 0:
            return True
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout


def _published_ports() -> set[int]:
    ports = set()
    for token in _docker("ps", "--format", "{{.Ports}}").replace(",", " ").split():
        if "->" in token:
            host = token.split("->")[0].rsplit(":", 1)[-1]
            if host.isdigit():
                ports.add(int(host))
    return ports


def _used_subnets() -> list[ipaddress.IPv4Network]:
    ids = _docker("network", "ls", "-q").split()
    if not ids:
        return []
    out = _docker("network", "inspect", *ids, "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}")
    nets = []
    for cidr in out.split():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return nets


def _other_instances_values(key: str, me: Path) -> set[str]:
    vals = set()
    for env in (me.parent).glob("*/.env"):
        if env.parent == me:
            continue
        for line in env.read_text().splitlines():
            if line.startswith(f"{key}="):
                vals.add(line.split("=", 1)[1])
    return vals


def pick_port(lo: int, hi: int, taken: set[str]) -> int:
    published = _published_ports()
    for p in range(lo, hi + 1):
        if p not in published and str(p) not in taken and not _port_in_use(p):
            return p
    raise RuntimeError(f"no free port in {lo}-{hi}")


def pick_subnet(pool: list[str], taken: set[str]) -> str:
    used = _used_subnets()
    for cidr in pool:
        net = ipaddress.ip_network(cidr)
        if cidr not in taken and not any(net.overlaps(u) for u in used):
            return cidr
    raise RuntimeError("no free lab subnet in the pool")


def build_env(instance: Instance, lab: dict[str, Any], keep: dict[str, str]) -> dict[str, str]:
    net_cfg = lab["network"]
    port = keep.get("SMB_PORT") or str(pick_port(*net_cfg["smb_port_range"], _other_instances_values("SMB_PORT", instance.root)))
    subnet = keep.get("LAB_SUBNET") or pick_subnet(net_cfg["subnet_pool"], _other_instances_values("LAB_SUBNET", instance.root))
    net = ipaddress.ip_network(subnet)

    def ip(octet: int) -> str:
        return str(net.network_address + octet)

    env: dict[str, str] = {
        "INSTANCE": instance.name,
        "LAB_DIR": str(instance.root.resolve()),
        "SMB_PORT": port,
        "LAB_SUBNET": subnet,
        "IP_GATEWAY": ip(1),
    }
    for svc, octet in lab["hosts"].items():
        env[f"IP_{svc.upper()}"] = ip(octet)
    for actor, a in lab["actors"].items():
        env[f"IP_{actor.upper().replace('-', '_')}"] = ip(a["octet"])
    env["SMB_IDENTITIES"] = ";".join(f"{name}:{','.join(groups)}" for name, groups in lab["identities"].items())
    for name in lab["identities"]:
        k = f"SMB_PW_{name.upper().replace('-', '_')}"
        env[k] = keep.get(k) or secrets.token_urlsafe(18)
    for role in ("ADMIN", "CLASSIFIER", "MATCHER", "INCIDENT", "READER"):
        k = f"LEDGER_PW_{role}"
        env[k] = keep.get(k) or secrets.token_urlsafe(18)
    env["SIM_KEY"] = keep.get("SIM_KEY") or secrets.token_hex(32)
    env["COLLECTOR_SOURCE"] = keep.get("COLLECTOR_SOURCE", "both")
    env["RENAME_WINDOW"] = keep.get("RENAME_WINDOW", "5")
    env["SIM_EPOCH"] = keep.get("SIM_EPOCH", "2026-11-02T00:00:00Z")
    return env


def init_instance(name: str) -> Instance:
    inst = Instance.get(name)
    lab = load_config("lab", specs_dir()).data
    keep = inst.env() if inst.env_file.exists() else {}
    for d in (inst.data / "finance", inst.data / "software", inst.logs, inst.staging, inst.feeds / "inbox",
              inst.feeds / "processed", inst.feeds / "rejected", inst.incidents / "inbox",
              inst.incidents / "rejected", inst.secrets):
        d.mkdir(parents=True, exist_ok=True)
    env = build_env(inst, lab, keep)
    text = "# Generated by dwta-lab init. Contains secrets: never commit.\n" + "".join(f"{k}={v}\n" for k, v in env.items())
    inst.env_file.write_text(text)
    os.chmod(inst.env_file, 0o600)
    for ident in lab["identities"]:
        f = inst.secrets / f"smb-{ident}"
        f.write_text(f"username = {ident}\npassword = {env['SMB_PW_' + ident.upper().replace('-', '_')]}\ndomain = DWTA\n")
        os.chmod(f, 0o600)
    return inst


def status(inst: Instance) -> list[dict[str, Any]]:
    out = inst.compose("ps", "-a", "--format", "json", capture=True).stdout.decode()
    rows = []
    for line in out.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
