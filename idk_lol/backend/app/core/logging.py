"""Structured application logging.

Logs are emitted as JSON to stdout. Sensitive financial data must never be
logged -- loggers receive safe metadata only (ids, actions, outcomes).
"""
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json

        log_record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
        # Attach safe extra fields if present
        for key in ("user_id", "institution_id", "action", "target_type", "target_id"):
            if hasattr(record, key):
                log_record[key] = getattr(record, key)
        return json.dumps(log_record, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # Reduce noise from third-party loggers
    for name in ("uvicorn", "sqlalchemy.engine", "passlib"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)