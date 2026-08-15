"""
Structured logging configuration with PII masking and correlation tracking.
"""
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict


SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


class StructuredAuditFormatter(logging.Formatter):
    """Formats log records as single-line structured JSON with automatic PII masking."""

    def format(self, record: logging.LogRecord) -> str:
        raw_message = record.getMessage()
        sanitized_message = SSN_PATTERN.sub("***-**-****", raw_message)
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_message,
            "module": record.module,
            "line": record.lineno,
        }
        if hasattr(record, "request_id"):
            payload["request_id"] = getattr(record, "request_id")
        if hasattr(record, "actor_id"):
            payload["actor_id"] = getattr(record, "actor_id")
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredAuditFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
