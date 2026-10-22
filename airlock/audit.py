"""Tamper-evident audit log: hash-chained JSON lines.

Every record carries seq, ts, prev_hash and hash, where
hash = sha256(prev_hash + canonical JSON of the record without "hash").
Editing, reordering or deleting any line breaks the chain from that point on.
Records must never hold raw prompt text or secrets: callers pass
Decision.to_record() plus hashes and metadata only.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64
_RESERVED = ("seq", "ts", "prev_hash", "hash")


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compute_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """Hash of a record, ignoring any "hash" key it already has."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(prev_hash.encode() + _canonical(body)).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Append-only hash chain stored as JSONL. Safe to share between threads."""

    def __init__(self, path: str) -> None:
        self.path = os.fspath(path)
        self._lock = threading.Lock()
        self._prev_hash, self._next_seq = self._recover()

    def _recover(self) -> tuple[str, int]:
        """Continue the chain from the last valid record of an existing file."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return GENESIS, 0
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                return str(rec["hash"]), int(rec["seq"]) + 1
            except (ValueError, KeyError, TypeError):
                continue
        return GENESIS, 0

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Chain and persist one record; returns the stored entry."""
        with self._lock:
            entry = {k: v for k, v in record.items() if k not in _RESERVED}
            entry["seq"] = self._next_seq
            entry["ts"] = _now()
            entry["prev_hash"] = self._prev_hash
            entry["hash"] = compute_hash(self._prev_hash, entry)
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n"

            parent = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(parent, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()

            self._prev_hash = entry["hash"]
            self._next_seq += 1
            return entry

    def verify(self) -> tuple[bool, int, int | None]:
        with self._lock:
            return verify(self.path)


def verify(path: str) -> tuple[bool, int, int | None]:
    """Check the whole chain.

    Returns (ok, records_checked, first_bad_seq). records_checked counts the
    records that verified before the first failure. A missing file is an empty,
    valid chain. Truncation of the tail cannot be detected without an external
    anchor (e.g. publishing the last hash).
    """
    try:
        with open(os.fspath(path), encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    except FileNotFoundError:
        return True, 0, None

    prev = GENESIS
    for expected_seq, line in enumerate(lines):
        try:
            rec = json.loads(line)
            ok = (
                isinstance(rec, dict)
                and rec.get("seq") == expected_seq
                and rec.get("prev_hash") == prev
                and rec.get("hash") == compute_hash(prev, rec)
            )
        except ValueError:
            ok = False
        if not ok:
            return False, expected_seq, expected_seq
        prev = rec["hash"]
    return True, len(lines), None
