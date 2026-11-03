"""Applies numbered SQL migrations once each and creates the per-service roles (LED-02, LED-03)."""

from __future__ import annotations

import os
from importlib import resources

import psycopg
from psycopg import sql

SERVICE_ROLES = {
    "dwta_classifier": "LEDGER_PW_CLASSIFIER",
    "dwta_matcher": "LEDGER_PW_MATCHER",
    "dwta_incident": "LEDGER_PW_INCIDENT",
    "dwta_reader": "LEDGER_PW_READER",
}
SCHEMA_VERSION = "1"


def _migrations() -> list[tuple[str, str]]:
    files = sorted(f for f in resources.files("dwta_ledger.migrations").iterdir() if f.name.endswith(".sql"))
    return [(f.name, f.read_text()) for f in files]


def ensure_roles(conn: psycopg.Connection, passwords: dict[str, str] | None = None) -> None:
    for role, env in SERVICE_ROLES.items():
        pw = (passwords or {}).get(role) or os.environ.get(env)
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        stmt = "ALTER ROLE {} WITH LOGIN PASSWORD {}" if exists else "CREATE ROLE {} WITH LOGIN PASSWORD {}"
        if pw:
            conn.execute(sql.SQL(stmt).format(sql.Identifier(role), sql.Literal(pw)))
        elif not exists:
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))


def migrate(conn: psycopg.Connection, passwords: dict[str, str] | None = None) -> list[str]:
    """Idempotent: returns the names of migrations applied by this call."""
    applied: list[str] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(4242)")
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        ensure_roles(conn, passwords)
        done = {r[0] if isinstance(r, tuple) else r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
        for name, text in _migrations():
            if name in done:
                continue
            conn.execute(text)
            conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
            applied.append(name)
        conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', %s) "
                     "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (SCHEMA_VERSION,))
    return applied


def check_schema(conn: psycopg.Connection) -> None:
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    found = row["value"] if isinstance(row, dict) else (row[0] if row else None)
    if found != SCHEMA_VERSION:
        raise RuntimeError(f"ledger schema_version {found!r}, expected {SCHEMA_VERSION!r}; run dwta-ledger migrate")
