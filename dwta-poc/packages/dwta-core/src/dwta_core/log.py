"""One-line JSON logs on stderr for every service."""

from __future__ import annotations

import json
import logging
import os
import sys

from .timeutil import iso, utcnow


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": iso(utcnow()), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        out.update(getattr(record, "fields", {}))
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


def setup(name: str) -> logging.Logger:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.environ.get("DWTA_LOG_LEVEL", "INFO"))
    return logging.getLogger(name)


def kv(**fields: object) -> dict[str, dict[str, object]]:
    """``log.info("msg", extra=kv(path=p))`` adds structured fields."""
    return {"fields": fields}
