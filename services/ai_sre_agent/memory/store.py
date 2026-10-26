"""Durable historical incident memory for FinStream AI-SRE."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from services.ai_sre_agent.models import (
    Incident,
    IncidentStatus,
    new_id,
    utc_now,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
)


class IncidentMemoryError(RuntimeError):
    """Incident memory could not be safely persisted or updated."""


class IncidentMemoryIntegrityError(
    IncidentMemoryError
):
    """Persisted incident memory contains invalid state."""


@dataclass(frozen=True, slots=True)
class IncidentMemoryRecord:
    """One durable historical AI-SRE investigation record."""

    memory_id: str
    incident_id: str
    fingerprint: str
    alert_name: str
    severity: str
    affected_service: str | None
    summary: str | None

    incident_status_at_recording: IncidentStatus

    started_at: datetime
    resolved_at: datetime | None

    selected_candidate_ids: tuple[str, ...]
    runbook_ids: tuple[str, ...]

    abstained: bool
    abstention_reason: str | None

    recorded_at: datetime

    final_status: IncidentStatus | None = None
    resolution_summary: str | None = None
    finalized_at: datetime | None = None


class SQLiteIncidentMemoryStore:
    """SQLite-backed durable incident memory.

    Historical memory is deliberately stored separately from current
    operational evidence. This store provides no execution authority
    and performs no remediation.
    """

    _FINAL_STATUSES = frozenset(
        {
            IncidentStatus.RESOLVED,
            IncidentStatus.FAILED,
            IncidentStatus.CLOSED,
        }
    )

    def __init__(
        self,
        path: str | Path,
    ) -> None:
        self._path = Path(path)

        self._path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    @property
    def path(self) -> Path:
        """Return the SQLite database path."""
        return self._path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=5.0,
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_memories (
                    incident_id TEXT PRIMARY KEY,
                    memory_id TEXT NOT NULL UNIQUE,

                    fingerprint TEXT NOT NULL,
                    alert_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    affected_service TEXT,
                    summary TEXT,

                    incident_status_at_recording TEXT NOT NULL,

                    started_at TEXT NOT NULL,
                    resolved_at TEXT,

                    selected_candidate_ids_json TEXT NOT NULL,
                    runbook_ids_json TEXT NOT NULL,

                    abstained INTEGER NOT NULL,
                    abstention_reason TEXT,

                    recorded_at TEXT NOT NULL,

                    final_status TEXT,
                    resolution_summary TEXT,
                    finalized_at TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_memories_service_finalized
                ON incident_memories (
                    affected_service,
                    finalized_at
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_memories_alert_finalized
                ON incident_memories (
                    alert_name,
                    finalized_at
                )
                """
            )

    @staticmethod
    def _decode_string_tuple(
        raw: str,
        *,
        field: str,
    ) -> tuple[str, ...]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IncidentMemoryIntegrityError(
                f"Incident memory contains invalid {field} JSON."
            ) from exc

        if (
            not isinstance(value, list)
            or any(
                not isinstance(item, str)
                or not item.strip()
                for item in value
            )
        ):
            raise IncidentMemoryIntegrityError(
                f"Incident memory contains invalid {field}."
            )

        normalized = tuple(
            item.strip()
            for item in value
        )

        if len(normalized) != len(set(normalized)):
            raise IncidentMemoryIntegrityError(
                f"Incident memory contains duplicate {field}."
            )

        return normalized

    @classmethod
    def _decode(
        cls,
        row: sqlite3.Row,
    ) -> IncidentMemoryRecord:
        try:
            abstained_raw = row["abstained"]

            if abstained_raw not in (0, 1):
                raise ValueError(
                    "Invalid abstention state."
                )

            selected_candidate_ids = (
                cls._decode_string_tuple(
                    row["selected_candidate_ids_json"],
                    field="selected candidate IDs",
                )
            )

            runbook_ids = cls._decode_string_tuple(
                row["runbook_ids_json"],
                field="runbook IDs",
            )

            abstained = bool(abstained_raw)
            abstention_reason = row[
                "abstention_reason"
            ]

            if abstained:
                if selected_candidate_ids:
                    raise ValueError(
                        "Abstained memory cannot contain "
                        "selected candidates."
                    )

                if (
                    abstention_reason is None
                    or not abstention_reason.strip()
                ):
                    raise ValueError(
                        "Abstained memory requires a reason."
                    )
            else:
                if not selected_candidate_ids:
                    raise ValueError(
                        "Selected memory requires candidates."
                    )

                if abstention_reason is not None:
                    raise ValueError(
                        "Selected memory cannot contain an "
                        "abstention reason."
                    )

            final_status = (
                IncidentStatus(
                    row["final_status"]
                )
                if row["final_status"] is not None
                else None
            )

            resolution_summary = row[
                "resolution_summary"
            ]

            finalized_at = (
                datetime.fromisoformat(
                    row["finalized_at"]
                )
                if row["finalized_at"] is not None
                else None
            )

            if final_status is None:
                if (
                    resolution_summary is not None
                    or finalized_at is not None
                ):
                    raise ValueError(
                        "Unfinalized memory contains final "
                        "outcome fields."
                    )
            else:
                if (
                    resolution_summary is None
                    or not resolution_summary.strip()
                    or finalized_at is None
                ):
                    raise ValueError(
                        "Finalized memory is incomplete."
                    )

            return IncidentMemoryRecord(
                memory_id=row["memory_id"],
                incident_id=row["incident_id"],
                fingerprint=row["fingerprint"],
                alert_name=row["alert_name"],
                severity=row["severity"],
                affected_service=row[
                    "affected_service"
                ],
                summary=row["summary"],
                incident_status_at_recording=(
                    IncidentStatus(
                        row[
                            "incident_status_at_recording"
                        ]
                    )
                ),
                started_at=datetime.fromisoformat(
                    row["started_at"]
                ),
                resolved_at=(
                    datetime.fromisoformat(
                        row["resolved_at"]
                    )
                    if row["resolved_at"] is not None
                    else None
                ),
                selected_candidate_ids=(
                    selected_candidate_ids
                ),
                runbook_ids=runbook_ids,
                abstained=abstained,
                abstention_reason=(
                    abstention_reason
                ),
                recorded_at=datetime.fromisoformat(
                    row["recorded_at"]
                ),
                final_status=final_status,
                resolution_summary=resolution_summary,
                finalized_at=finalized_at,
            )

        except (
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise IncidentMemoryIntegrityError(
                "Incident memory contains an invalid record."
            ) from exc

    @staticmethod
    def _selection_values(
        selection: CandidateSelectionOutcome,
    ) -> tuple[
        tuple[str, ...],
        tuple[str, ...],
    ]:
        if selection.abstained:
            if selection.selections:
                raise IncidentMemoryError(
                    "Abstained selection cannot contain "
                    "candidate selections."
                )

            if (
                selection.abstention_reason is None
                or not selection.abstention_reason.strip()
            ):
                raise IncidentMemoryError(
                    "Abstained selection requires a reason."
                )

            return (), ()

        if not selection.selections:
            raise IncidentMemoryError(
                "Non-abstaining selection requires at least "
                "one candidate."
            )

        if selection.abstention_reason is not None:
            raise IncidentMemoryError(
                "Non-abstaining selection cannot contain an "
                "abstention reason."
            )

        candidate_ids = tuple(
            selected.candidate_id
            for selected in selection.selections
        )

        if len(candidate_ids) != len(
            set(candidate_ids)
        ):
            raise IncidentMemoryError(
                "Incident memory cannot persist duplicate "
                "candidate IDs."
            )

        runbook_ids: list[str] = []

        for selected in selection.selections:
            for citation in (
                selected.runbook_citations
            ):
                if citation.runbook_id not in runbook_ids:
                    runbook_ids.append(
                        citation.runbook_id
                    )

        return (
            candidate_ids,
            tuple(runbook_ids),
        )

    def get(
        self,
        incident_id: str,
    ) -> IncidentMemoryRecord | None:
        """Return one persisted incident memory."""
        incident_id = incident_id.strip()

        if not incident_id:
            raise ValueError(
                "incident_id must not be empty."
            )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM incident_memories
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()

        if row is None:
            return None

        return self._decode(row)

    def record_investigation(
        self,
        *,
        incident: Incident,
        selection: CandidateSelectionOutcome,
    ) -> IncidentMemoryRecord:
        """Persist one completed constrained investigation.

        This captures historical reasoning state only. It does not
        establish current operational truth and grants no execution
        authority.
        """
        (
            candidate_ids,
            runbook_ids,
        ) = self._selection_values(
            selection
        )

        memory_id = new_id("mem")
        recorded_at = utc_now()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO incident_memories (
                        incident_id,
                        memory_id,
                        fingerprint,
                        alert_name,
                        severity,
                        affected_service,
                        summary,
                        incident_status_at_recording,
                        started_at,
                        resolved_at,
                        selected_candidate_ids_json,
                        runbook_ids_json,
                        abstained,
                        abstention_reason,
                        recorded_at
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        incident.incident_id,
                        memory_id,
                        incident.fingerprint,
                        incident.alert_name,
                        incident.severity,
                        incident.affected_service,
                        incident.summary,
                        incident.status.value,
                        incident.started_at.isoformat(),
                        (
                            incident.resolved_at.isoformat()
                            if incident.resolved_at
                            is not None
                            else None
                        ),
                        json.dumps(
                            list(candidate_ids),
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            list(runbook_ids),
                            separators=(",", ":"),
                        ),
                        int(selection.abstained),
                        selection.abstention_reason,
                        recorded_at.isoformat(),
                    ),
                )

        except sqlite3.IntegrityError as exc:
            raise IncidentMemoryError(
                "Incident investigation has already been "
                "persisted."
            ) from exc

        result = self.get(
            incident.incident_id
        )

        if result is None:
            raise IncidentMemoryError(
                "Incident memory was not persisted."
            )

        return result

    def finalize(
        self,
        *,
        incident_id: str,
        final_status: IncidentStatus,
        resolution_summary: str,
    ) -> IncidentMemoryRecord:
        """Finalize a historical incident exactly once."""
        incident_id = incident_id.strip()
        resolution_summary = (
            resolution_summary.strip()
        )

        if not incident_id:
            raise ValueError(
                "incident_id must not be empty."
            )

        if final_status not in self._FINAL_STATUSES:
            raise IncidentMemoryError(
                "Incident memory final status must be "
                "RESOLVED, FAILED, or CLOSED."
            )

        if not resolution_summary:
            raise IncidentMemoryError(
                "Incident memory finalization requires a "
                "resolution summary."
            )

        finalized_at = utc_now()

        connection = self._connect()

        try:
            connection.execute(
                "BEGIN IMMEDIATE"
            )

            existing = connection.execute(
                """
                SELECT final_status
                FROM incident_memories
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()

            if existing is None:
                raise IncidentMemoryError(
                    "Incident memory does not exist."
                )

            if existing["final_status"] is not None:
                raise IncidentMemoryError(
                    "Incident memory has already been "
                    "finalized."
                )

            connection.execute(
                """
                UPDATE incident_memories
                SET final_status = ?,
                    resolution_summary = ?,
                    finalized_at = ?
                WHERE incident_id = ?
                """,
                (
                    final_status.value,
                    resolution_summary,
                    finalized_at.isoformat(),
                    incident_id,
                ),
            )

            connection.commit()

        except IncidentMemoryError:
            connection.rollback()
            raise

        finally:
            connection.close()

        result = self.get(
            incident_id
        )

        if result is None:
            raise IncidentMemoryError(
                "Finalized incident memory disappeared."
            )

        return result

    def recent_finalized(
        self,
        *,
        limit: int = 10,
        affected_service: str | None = None,
    ) -> tuple[IncidentMemoryRecord, ...]:
        """Return recent finalized memories only.

        Unfinalized investigations are intentionally excluded from
        historical retrieval.
        """
        if limit < 1:
            raise ValueError(
                "limit must be at least 1."
            )

        parameters: list[object] = []

        query = """
            SELECT *
            FROM incident_memories
            WHERE final_status IS NOT NULL
        """

        if affected_service is not None:
            affected_service = (
                affected_service.strip()
            )

            if not affected_service:
                raise ValueError(
                    "affected_service must not be blank."
                )

            query += """
                AND affected_service = ?
            """

            parameters.append(
                affected_service
            )

        query += """
            ORDER BY finalized_at DESC, incident_id ASC
            LIMIT ?
        """

        parameters.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                query,
                tuple(parameters),
            ).fetchall()

        return tuple(
            self._decode(row)
            for row in rows
        )
