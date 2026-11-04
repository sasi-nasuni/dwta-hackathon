#!/usr/bin/env python3
"""Local demo runner for the DwTA attack simulation.

A tiny stdlib HTTP service on the Mac that the Portal UI calls to start the realistic multi-account ransomware
simulation and to poll its progress. The simulation drives SMB from the lab VMs, so it must run on the host
(with uv, the repo and the SSH access) - never inside a Portal container. The Portal page talks to this service
directly on 127.0.0.1, so no SSH keys or lab secrets ever enter the Portal.

Endpoints (JSON):
  POST /run      start a run (409 if one is already in progress). The share is never modified beforehand.
  GET  /status   current state: idle | running | done | error, with progress, elapsed and ETA
  POST /reset    clear a finished run back to idle (does nothing while running)

Run it before the demo:
  python3 tools/demo-runner/server.py            # binds 127.0.0.1:8899
Environment:
  DEMO_RUNNER_PORT    default 8899
  DEMO_ALLOW_ORIGIN   default http://localhost:3000 (CORS for the Portal SPA)
  DEMO_SCENARIO       default compromised-accounts-filer
  DEMO_INSTANCE       default filer
  DEMO_TOTAL_SECONDS  default 390 (ETA baseline; refined from real step progress)
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]  # dwta-poc/
PORT = int(os.environ.get("DEMO_RUNNER_PORT", "8899"))
ALLOW_ORIGIN = os.environ.get("DEMO_ALLOW_ORIGIN", "http://localhost:3000")
SCENARIO = os.environ.get("DEMO_SCENARIO", "compromised-accounts-filer")
INSTANCE = os.environ.get("DEMO_INSTANCE", "filer")
TOTAL_SECONDS = float(os.environ.get("DEMO_TOTAL_SECONDS", "390"))

STEP_LINE = re.compile(r"^\s+D\d+\s")          # a completed scenario step, e.g. "  D7 02:00  encrypt ..."
STEP_COUNT = re.compile(r",\s*(\d+)\s+steps")  # "scenario ..., 13 steps, ..."
RP_INCIDENT = re.compile(r"new RP incident|incident_detected")


class Run:
    """State of a single simulation run, updated by the worker thread and read by /status."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.state = "idle"          # idle | running | done | error
        self.phase = ""              # wiping | simulating | ""
        self.started_at = 0.0
        self.finished_at = 0.0
        self.steps_total = 13
        self.steps_done = 0
        self.current = ""
        self.ok: bool | None = None
        self.message = ""

    def snapshot(self) -> dict:
        with self.lock:
            now = time.time()
            elapsed = (self.finished_at or now) - self.started_at if self.started_at else 0.0
            by_time = min(0.98, elapsed / TOTAL_SECONDS) if self.state == "running" else 0.0
            by_steps = (self.steps_done / self.steps_total) if self.steps_total else 0.0
            progress = 1.0 if self.state == "done" else (0.0 if self.state == "idle" else max(by_time, by_steps))
            if self.steps_done > 2 and self.state == "running":
                eta = max(0.0, elapsed / max(by_steps, 1e-6) - elapsed)
            else:
                eta = max(0.0, TOTAL_SECONDS - elapsed) if self.state == "running" else 0.0
            return {
                "state": self.state,
                "phase": self.phase,
                "progress": round(progress, 3),
                "steps_total": self.steps_total,
                "steps_done": self.steps_done,
                "current": self.current,
                "elapsed_seconds": round(elapsed),
                "eta_seconds": round(eta),
                "ok": self.ok,
                "message": self.message,
                "scenario": SCENARIO,
            }


RUN = Run()


def worker() -> None:
    with RUN.lock:
        RUN.state = "running"
        RUN.phase = "simulating"
        RUN.started_at = time.time()
        RUN.current = "Starting the simulated week"
    try:
        cmd = ["uv", "run", "--project", "tools/dwta-sim", "dwta-sim", "-i", INSTANCE, "run", SCENARIO]
        proc = subprocess.Popen(cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        assert proc.stdout is not None
        tail: list[str] = []
        log_path = Path(__file__).with_name("last-run.log")
        with log_path.open("w") as log:
            for line in proc.stdout:
                log.write(line)
                log.flush()
                line = line.rstrip()
                if not line or "UV_NATIVE_TLS" in line:
                    continue
                tail.append(line)
                del tail[:-25]
                m = STEP_COUNT.search(line)
                if m:
                    with RUN.lock:
                        RUN.steps_total = int(m.group(1))
                if STEP_LINE.match(line):
                    with RUN.lock:
                        RUN.steps_done += 1
                        RUN.current = " ".join(line.split())
                elif RP_INCIDENT.search(line):
                    with RUN.lock:
                        RUN.current = "Ransomware Protection raised the incident"
        rc = proc.wait()
        with RUN.lock:
            RUN.finished_at = time.time()
            RUN.ok = rc == 0
            RUN.state = "done" if rc == 0 else "error"
            RUN.phase = ""
            RUN.current = "Simulation complete" if rc == 0 else "Simulation failed"
            RUN.message = "" if rc == 0 else f"exit {rc}: {tail[-1] if tail else 'see last-run.log'}"[:300]
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        with RUN.lock:
            RUN.finished_at = time.time()
            RUN.ok = False
            RUN.state = "error"
            RUN.phase = ""
            RUN.current = "Simulation failed"
            RUN.message = str(exc)[:300]


class Handler(BaseHTTPRequestHandler):
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server naming
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/status":
            self._json(200, RUN.snapshot())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length") or 0)
        if length:  # drain the request body; the endpoints take no parameters
            self.rfile.read(length)
        if path == "/run":
            with RUN.lock:
                if RUN.state == "running":
                    self._json(409, {"error": "a simulation is already running", **RUN.snapshot()})
                    return
                RUN.reset()
            threading.Thread(target=worker, daemon=True).start()
            time.sleep(0.1)
            self._json(202, RUN.snapshot())
        elif path == "/reset":
            with RUN.lock:
                if RUN.state != "running":
                    RUN.reset()
            self._json(200, RUN.snapshot())
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *_args) -> None:  # quiet
        pass


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"DwTA demo runner on http://127.0.0.1:{PORT}  (scenario={SCENARIO}, CORS={ALLOW_ORIGIN})")
    print("  POST /run   GET /status   POST /reset")
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
