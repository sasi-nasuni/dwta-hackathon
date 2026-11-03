"""Connections to the ledger (Postgres 16). Settings come from DWTA_DB_* environment variables."""

from __future__ import annotations

import os
import time

import psycopg
from psycopg.rows import dict_row


def dsn_from_env(user: str | None = None, password: str | None = None) -> str:
    e = os.environ
    return psycopg.conninfo.make_conninfo(
        host=e.get("DWTA_DB_HOST", "localhost"),
        port=e.get("DWTA_DB_PORT", "5432"),
        dbname=e.get("DWTA_DB_NAME", "dwta"),
        user=user or e.get("DWTA_DB_USER", "dwta_admin"),
        password=password or e.get("DWTA_DB_PASSWORD", ""),
        application_name=e.get("DWTA_SERVICE", "dwta"),
    )


def connect(dsn: str | None = None, retry_for: float = 60.0) -> psycopg.Connection:
    """Connects with dict rows; retries while the database is starting (services start in any order).

    Autocommit: single statements commit on their own and every ``with conn.transaction():`` block is a real
    transaction (never a savepoint inside an implicit one).
    """
    deadline = time.monotonic() + retry_for
    while True:
        try:
            return psycopg.connect(dsn or dsn_from_env(), row_factory=dict_row, autocommit=True)
        except psycopg.OperationalError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
