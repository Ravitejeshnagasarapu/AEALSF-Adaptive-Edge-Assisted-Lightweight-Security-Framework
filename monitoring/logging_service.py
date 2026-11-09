from __future__ import annotations
import json
import logging
import sys
import time
from typing import Dict


class StructuredLogger:

    def __init__(self, name: str = "AEALSF", level: str = "INFO") -> None:
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    def info(self, event: str, **fields: object) -> None:
        self._emit("INFO", event, fields)

    def warning(self, event: str, **fields: object) -> None:
        self._emit("WARNING", event, fields)

    def error(self, event: str, **fields: object) -> None:
        self._emit("ERROR", event, fields)

    def _emit(self, severity: str, event: str, fields: Dict[str, object]) -> None:
        record = {
            "ts": round(time.time(), 4),
            "severity": severity,
            "event": event,
            **fields,
        }
        self.logger.log(
            getattr(logging, severity, logging.INFO), json.dumps(record, sort_keys=True)
        )


def get_logger(name: str = "AEALSF") -> StructuredLogger:
    return StructuredLogger(name=name)
