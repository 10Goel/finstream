"""Tamper-evident audit journal for FinStream AI-SRE."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from services.ai_sre_agent.models import (
    new_id,
    utc_now,
)

_GENESIS_HASH = "0" * 64


class AuditEventType(str, Enum):
    """Security-relevant AI-SRE lifecycle events."""

    PROPOSAL_CREATED = "PROPOSAL_CREATED"
    PROPOSAL_SUBMITTED = "PROPOSAL_SUBMITTED"
    PROPOSAL_APPROVED = "PROPOSAL_APPROVED"
    PROPOSAL_REJECTED = "PROPOSAL_REJECTED"

    AUTHORIZATION_ISSUED = "AUTHORIZATION_ISSUED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"

    PERMIT_ISSUED = "PERMIT_ISSUED"
    PERMIT_CONSUMED = "PERMIT_CONSUMED"

    KUBERNETES_DRY_RUN_PREPARED = (
        "KUBERNETES_DRY_RUN_PREPARED"
    )

    EXECUTION_SAFETY_PASSED = "EXECUTION_SAFETY_PASSED"
    EXECUTION_SAFETY_BLOCKED = "EXECUTION_SAFETY_BLOCKED"

    EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"

    EXECUTION_VERIFICATION_PASSED = (
        "EXECUTION_VERIFICATION_PASSED"
    )
    EXECUTION_VERIFICATION_FAILED = (
        "EXECUTION_VERIFICATION_FAILED"
    )


class AuditIntegrityError(RuntimeError):
    """Audit journal integrity validation failed."""


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One immutable audit record."""

    sequence: int
    event_id: str
    timestamp: str
    event_type: AuditEventType
    actor: str
    incident_id: str
    proposal_id: str | None
    authorization_id: str | None
    permit_id: str | None
    details: dict[str, Any]
    previous_hash: str
    record_hash: str


def _json_safe(value: Any) -> Any:
    """Convert supported domain values into canonical JSON values."""
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _json_safe(item)
            for item in value
        ]

    if value is None or isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    raise TypeError(
        f"Unsupported audit detail type: {type(value).__name__}"
    )


class JsonlAuditLog:
    """Append-only SHA-256 chained JSONL audit journal."""

    def __init__(
        self,
        path: str | Path,
    ) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def _canonical_bytes(
        payload: dict[str, Any],
    ) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _calculate_hash(
        cls,
        payload: dict[str, Any],
    ) -> str:
        return hashlib.sha256(
            cls._canonical_bytes(payload)
        ).hexdigest()

    @staticmethod
    def _record_without_hash(
        *,
        sequence: int,
        event_id: str,
        timestamp: str,
        event_type: AuditEventType,
        actor: str,
        incident_id: str,
        proposal_id: str | None,
        authorization_id: str | None,
        permit_id: str | None,
        details: dict[str, Any],
        previous_hash: str,
    ) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type.value,
            "actor": actor,
            "incident_id": incident_id,
            "proposal_id": proposal_id,
            "authorization_id": authorization_id,
            "permit_id": permit_id,
            "details": _json_safe(details),
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _decode_record(
        payload: dict[str, Any],
    ) -> AuditRecord:
        try:
            return AuditRecord(
                sequence=int(payload["sequence"]),
                event_id=str(payload["event_id"]),
                timestamp=str(payload["timestamp"]),
                event_type=AuditEventType(
                    payload["event_type"]
                ),
                actor=str(payload["actor"]),
                incident_id=str(payload["incident_id"]),
                proposal_id=payload.get("proposal_id"),
                authorization_id=payload.get(
                    "authorization_id"
                ),
                permit_id=payload.get("permit_id"),
                details=dict(payload["details"]),
                previous_hash=str(
                    payload["previous_hash"]
                ),
                record_hash=str(
                    payload["record_hash"]
                ),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise AuditIntegrityError(
                "Audit journal contains an invalid record."
            ) from exc

    def _read_raw(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []

        records: list[dict[str, Any]] = []

        try:
            with self._path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                for line_number, line in enumerate(
                    handle,
                    start=1,
                ):
                    if not line.strip():
                        raise AuditIntegrityError(
                            "Audit journal contains a blank "
                            f"record at line {line_number}."
                        )

                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise AuditIntegrityError(
                            "Audit journal contains malformed "
                            f"JSON at line {line_number}."
                        ) from exc

                    if not isinstance(payload, dict):
                        raise AuditIntegrityError(
                            "Audit journal record must be "
                            "a JSON object."
                        )

                    records.append(payload)

        except OSError as exc:
            raise AuditIntegrityError(
                "Unable to read audit journal."
            ) from exc

        return records

    def verify(self) -> int:
        """Verify sequence numbers and the complete hash chain."""
        raw_records = self._read_raw()

        expected_previous_hash = _GENESIS_HASH

        for expected_sequence, payload in enumerate(
            raw_records,
            start=1,
        ):
            record = self._decode_record(
                payload
            )

            if record.sequence != expected_sequence:
                raise AuditIntegrityError(
                    "Audit journal sequence is invalid."
                )

            if (
                record.previous_hash
                != expected_previous_hash
            ):
                raise AuditIntegrityError(
                    "Audit journal hash chain is broken."
                )

            unhashed = dict(payload)
            supplied_hash = unhashed.pop(
                "record_hash",
                None,
            )

            if supplied_hash is None:
                raise AuditIntegrityError(
                    "Audit journal record hash is missing."
                )

            calculated_hash = self._calculate_hash(
                unhashed
            )

            if supplied_hash != calculated_hash:
                raise AuditIntegrityError(
                    "Audit journal record hash mismatch."
                )

            expected_previous_hash = supplied_hash

        return len(raw_records)

    def read_all(self) -> tuple[AuditRecord, ...]:
        """Read records only after verifying the entire chain."""
        self.verify()

        return tuple(
            self._decode_record(payload)
            for payload in self._read_raw()
        )

    def append(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        incident_id: str,
        proposal_id: str | None = None,
        authorization_id: str | None = None,
        permit_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Append exactly one integrity-linked audit record."""
        actor = actor.strip()
        incident_id = incident_id.strip()

        if not actor:
            raise ValueError(
                "Audit actor must not be empty."
            )

        if not incident_id:
            raise ValueError(
                "Audit incident ID must not be empty."
            )

        self._path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Verify the existing journal before extending it.
        existing = self.read_all()

        sequence = len(existing) + 1

        previous_hash = (
            existing[-1].record_hash
            if existing
            else _GENESIS_HASH
        )

        event_id = new_id("audit")
        timestamp = utc_now().isoformat()

        unhashed = self._record_without_hash(
            sequence=sequence,
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            proposal_id=proposal_id,
            authorization_id=authorization_id,
            permit_id=permit_id,
            details=details or {},
            previous_hash=previous_hash,
        )

        record_hash = self._calculate_hash(
            unhashed
        )

        payload = {
            **unhashed,
            "record_hash": record_hash,
        }

        try:
            with self._path.open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditIntegrityError(
                "Unable to append audit record."
            ) from exc

        return self._decode_record(
            payload
        )
