"""Simulator target: a real Nasuni Edge (instance name ``filer``).

* SMB clients are the lab's client containers on Docker's default network; they reach the Edge's share at
  ``//<FILER>/<share>`` (all of them appear to the Edge with this Mac's IP, Docker Desktop NAT).
* The simulated clock, threat feeds and injected incidents go to the Edge over SSH (``/var/nasuni/dwta``).
* Ransomware Protection on the Edge detects the encryption for real; ``raise_incident`` is only the demo fallback.

Settings come from ``lab/filer/.env`` (written by unity/python3/dwta/deploy/setup-lab-volume.sh).
"""

from __future__ import annotations

import json
import secrets
import shlex
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dwta_core.timeutil import iso, parse_iso

from .lab import Instance, repo_root

DWTA_ROOT = "/var/nasuni/dwta"
CLIENTS = ("client-admin", "client-jdoe", "client-asmith", "client-attack")
IDENTITY_USER = {"admin": "SMB_PW_ITADMIN", "jdoe": "SMB_PW_JDOE", "asmith": "SMB_PW_ASMITH",
                 "svc-backup": "SMB_PW_SVC_BACKUP"}
SMB_USERNAME = {"admin": "itadmin"}  # the simulator's "admin" identity logs in as the Edge's itadmin


class FilerInstance(Instance):
    def env(self) -> dict[str, str]:
        out = {}
        if not self.env_file.exists():
            raise FileNotFoundError(f"{self.env_file} missing; run unity/python3/dwta/deploy/setup-lab-volume.sh")
        for line in self.env_file.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        key = self.root / "sim.key"
        if not key.exists():
            key.write_text(secrets.token_hex(32))
            key.chmod(0o600)
        out["SIM_KEY"] = key.read_text().strip()
        return out

    @property
    def smb_host(self) -> str:  # type: ignore[override]
        return self.env()["FILER"]

    # ------------------------------------------------------------------ local client containers
    def compose_cmd(self, *args: str) -> list[str]:
        return ["docker", "compose", "-p", "dwta-filer", "-f",
                str(repo_root() / "deploy" / "compose" / "filer-clients.yml"), *args]

    def compose(self, *args: str, check: bool = True, capture: bool = False, input_bytes: bytes | None = None):
        env = {"LAB_DIR": str(self.root.resolve()), "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}
        return subprocess.run(self.compose_cmd(*args), check=check, capture_output=capture, input=input_bytes,
                              env={**__import__("os").environ, **env})

    def write_secrets(self) -> None:
        env = self.env()
        self.secrets.mkdir(parents=True, exist_ok=True)
        for identity, var in IDENTITY_USER.items():
            # with AD (SMB_DOMAIN set) each simulator identity is mapped to a domain account: SMB_USER_<IDENTITY>
            user = env.get(var.replace("SMB_PW_", "SMB_USER_").replace("_ITADMIN", "_ADMIN"),
                           SMB_USERNAME.get(identity, identity))
            text = f"username = {user}\npassword = {env[var]}\n"
            if env.get("SMB_DOMAIN"):
                text += f"domain = {env['SMB_DOMAIN']}\n"
            f = self.secrets / f"smb-{identity}"
            f.write_text(text)
            f.chmod(0o600)
        self.staging.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ Edge over SSH
    def ssh(self, command: str, input_text: str | None = None, check: bool = True) -> str:
        env = self.env()
        argv = ["ssh", "-o", "BatchMode=yes", "-p", env.get("FILER_SSH_PORT", "22"), f"root@{env['FILER']}", command]
        p = subprocess.run(argv, input=input_text, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"ssh {command[:60]!r} failed: {p.stderr.strip()[:300]}")
        return p.stdout

    def legacy(self, route: str, params: dict | None = None) -> dict:
        out = self.ssh(f"curl -s -m 300 -X POST http://127.0.0.1:8765/{shlex.quote(route)} "
                       f"-H 'Content-Type: application/json' -d @-", input_text=json.dumps(params or {}))
        body = json.loads(out)
        if body.get("result") != "success":
            raise RuntimeError(f"{route}: {body.get('error') or body}")
        return body.get("data")

    def append_clock(self, run_id: str, sim_now, wall) -> None:
        line = json.dumps({"run_id": run_id, "sim_now": iso(sim_now), "wall_anchor": iso(wall)})
        self.ssh(f"mkdir -p {DWTA_ROOT}/run && cat >> {DWTA_ROOT}/run/simclock.jsonl", input_text=line + "\n")
        local = self.run / "simclock.jsonl"
        local.parent.mkdir(parents=True, exist_ok=True)
        with local.open("a") as fh:
            fh.write(line + "\n")

    def measure_skew(self) -> timedelta:
        best = None
        for _ in range(3):
            t0 = datetime.now(UTC)
            remote = parse_iso(self.ssh("date -u +%Y-%m-%dT%H:%M:%S.%6NZ").strip())
            t1 = datetime.now(UTC)
            if best is None or (t1 - t0) < best[0]:
                best = (t1 - t0, remote - (t0 + (t1 - t0) / 2))
        return best[1]

    def publish_feed(self, name: str, text: str) -> str:
        inbox = f"{DWTA_ROOT}/feeds/inbox"
        self.ssh(f"mkdir -p {inbox} && cat > {inbox}/.{name}.tmp && mv {inbox}/.{name}.tmp {inbox}/{name}", input_text=text)
        return f"filer:{inbox}/{name}"

    def raise_incident(self, incident: dict) -> str:
        """Demo fallback when Ransomware Protection did not fire: inject through the dwta.incident.inject route."""
        env = self.env()
        data = self.legacy("dwta.incident.inject", {
            "volume_guid": env["FILER_VOLUME_GUID"], "detected_at": incident["detected_sim_ts"],
            "user": incident.get("user"), "client_ip": incident.get("client_ip"),
            "client_name": incident.get("client_name")})
        return f"filer:dwta incident {data['incident']['incident_id']}"

    def snapshot(self) -> dict:
        guid = self.env()["FILER_VOLUME_GUID"]
        return {"forcesnap": self.legacy("volumes.forcesnap", {"guid": guid, "blocking": True})}

    def safety_check(self) -> None:
        env = self.env()
        vols = self.legacy("volumes.list")
        if not any(v.get("guid") == env["FILER_VOLUME_GUID"] for v in vols):
            raise RuntimeError(f"volume {env['FILER_VOLUME_GUID']} not found on {env['FILER']}; refusing to run")
        self.write_secrets()
        running = self.compose("ps", "-q", capture=True).stdout.decode().split()
        if len(running) < len(CLIENTS):
            self.compose("up", "-d", "--build", *CLIENTS)


def ensure_dirs(root: Path) -> None:
    for d in ("run", "staging", "secrets"):
        (root / d).mkdir(parents=True, exist_ok=True)
