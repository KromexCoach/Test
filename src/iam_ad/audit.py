"""Journal d'audit : une ligne JSON par événement, sur la sortie standard.

Aucun secret n'y figure (ni mot de passe, ni jeton, ni clé d'API).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

_audit_logger = logging.getLogger("iam_ad.audit")


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s %(message)s"
        )
    if not _audit_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _audit_logger.addHandler(handler)
        _audit_logger.setLevel(logging.INFO)
        _audit_logger.propagate = False


def audit(event: str, outcome: str, **fields: str | None) -> None:
    record = {
        "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "event": event,
        "outcome": outcome,
        **{key: value for key, value in fields.items() if value is not None},
    }
    _audit_logger.info(json.dumps(record, ensure_ascii=False))
