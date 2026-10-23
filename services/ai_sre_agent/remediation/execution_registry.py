"""Durable execution claim registry for FinStream AI-SRE."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from services.ai_sre_agent.models import (
    Incident,
    new_id,
    utc_now,
)
from services.ai_sre_agent.remediation.approval import (
    RemediationProposal,
)
from services.ai_sre_agent.remediation.authorization import (
    ExecutionAuthorization,
)
from services.ai_sre_agent.remediation.permit import (
    ExecutionPermit,
)
from services.ai_sre_agent.remediation.safety import (
    ExecutionSafetyApproval,
    ExecutionSafetyGate,
    ExecutionSafetySnapshot,
)


class ExecutionClaimStatus(str, Enum):
    """Persistent execution claim lifecycle."""

    CLAIMED = "CLAIMED"
    RELEASED = "RELEASED"


class ExecutionClaimError(RuntimeError):
    """An execution claim could not be acquired safely."""


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    """Durable claim for one future remediation attempt."""

    claim_id: str
    incident_id: str
    authorization_id: str
    permit_id: str
    safety_approval_id: str

    action_id: str
    namespace: str
    deployment: str

    status: ExecutionClaimStatus

    claimed_at: datetime
    released_at: datetime | None = None
    release_reason: str | None = None


class SQLiteExecutionRegistry:
    """Atomic replay and concurrency protection.

    The registry deliberately performs no remediation execution.
    """

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
                CREATE TABLE IF NOT EXISTS execution_claims (
                    permit_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL UNIQUE,
                    incident_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    safety_approval_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    deployment TEXT NOT NULL,
                    status TEXT NOT NULL,
                    claimed_at TEXT NOT NULL,
                    released_at TEXT,
                    release_reason TEXT
                )
                """
            )

    @staticmethod
    def _decode(
        row: sqlite3.Row,
    ) -> ExecutionClaim:
        return ExecutionClaim(
            claim_id=row["claim_id"],
            incident_id=row["incident_id"],
            authorization_id=row["authorization_id"],
            permit_id=row["permit_id"],
            safety_approval_id=row["safety_approval_id"],
            action_id=row["action_id"],
            namespace=row["namespace"],
            deployment=row["deployment"],
            status=ExecutionClaimStatus(
                row["status"]
            ),
            claimed_at=datetime.fromisoformat(
                row["claimed_at"]
            ),
            released_at=(
                datetime.fromisoformat(
                    row["released_at"]
                )
                if row["released_at"] is not None
                else None
            ),
            release_reason=row["release_reason"],
        )

    def active_claim_count(
        self,
        *,
        namespace: str,
        deployment: str,
    ) -> int:
        """Return active claims for the target."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM execution_claims
                WHERE namespace = ?
                  AND deployment = ?
                  AND status = ?
                """,
                (
                    namespace,
                    deployment,
                    ExecutionClaimStatus.CLAIMED.value,
                ),
            ).fetchone()

        assert row is not None

        return int(row["total"])

    def get_by_permit(
        self,
        permit_id: str,
    ) -> ExecutionClaim | None:
        """Read an existing durable claim."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM execution_claims
                WHERE permit_id = ?
                """,
                (permit_id,),
            ).fetchone()

        if row is None:
            return None

        return self._decode(row)

    def claim(
        self,
        *,
        incident: Incident,
        proposal: RemediationProposal,
        authorization: ExecutionAuthorization,
        permit: ExecutionPermit,
        snapshot: ExecutionSafetySnapshot,
        safety_approval: ExecutionSafetyApproval,
    ) -> ExecutionClaim:
        """Atomically claim one remediation execution attempt."""
        ExecutionSafetyGate.validate(
            incident=incident,
            proposal=proposal,
            authorization=authorization,
            permit=permit,
            snapshot=snapshot,
            approval=safety_approval,
        )

        claim_id = new_id("claim")
        claimed_at = utc_now()

        connection = self._connect()

        try:
            connection.execute(
                "BEGIN IMMEDIATE"
            )

            existing = connection.execute(
                """
                SELECT permit_id
                FROM execution_claims
                WHERE permit_id = ?
                """,
                (permit.permit_id,),
            ).fetchone()

            if existing is not None:
                raise ExecutionClaimError(
                    "Execution permit has already been claimed."
                )

            active = connection.execute(
                """
                SELECT claim_id
                FROM execution_claims
                WHERE namespace = ?
                  AND deployment = ?
                  AND status = ?
                LIMIT 1
                """,
                (
                    safety_approval.namespace,
                    safety_approval.deployment,
                    ExecutionClaimStatus.CLAIMED.value,
                ),
            ).fetchone()

            if active is not None:
                raise ExecutionClaimError(
                    "Another execution already holds the "
                    "target claim."
                )

            connection.execute(
                """
                INSERT INTO execution_claims (
                    permit_id,
                    claim_id,
                    incident_id,
                    authorization_id,
                    safety_approval_id,
                    action_id,
                    namespace,
                    deployment,
                    status,
                    claimed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    permit.permit_id,
                    claim_id,
                    incident.incident_id,
                    authorization.authorization_id,
                    safety_approval.safety_approval_id,
                    proposal.action_id,
                    safety_approval.namespace,
                    safety_approval.deployment,
                    ExecutionClaimStatus.CLAIMED.value,
                    claimed_at.isoformat(),
                ),
            )

            connection.commit()

        except ExecutionClaimError:
            connection.rollback()
            raise

        except sqlite3.IntegrityError as exc:
            connection.rollback()

            raise ExecutionClaimError(
                "Execution claim conflicts with existing "
                "durable state."
            ) from exc

        finally:
            connection.close()

        claim = self.get_by_permit(
            permit.permit_id
        )

        if claim is None:
            raise ExecutionClaimError(
                "Execution claim was not persisted."
            )

        return claim

    def release(
        self,
        *,
        claim_id: str,
        reason: str,
    ) -> ExecutionClaim:
        """Release a claim without making its permit reusable."""
        reason = reason.strip()

        if not reason:
            raise ExecutionClaimError(
                "Execution claim release requires a reason."
            )

        released_at = utc_now()

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM execution_claims
                WHERE claim_id = ?
                """,
                (claim_id,),
            ).fetchone()

            if row is None:
                raise ExecutionClaimError(
                    "Execution claim does not exist."
                )

            claim = self._decode(row)

            if (
                claim.status
                is not ExecutionClaimStatus.CLAIMED
            ):
                raise ExecutionClaimError(
                    "Execution claim is not active."
                )

            connection.execute(
                """
                UPDATE execution_claims
                SET status = ?,
                    released_at = ?,
                    release_reason = ?
                WHERE claim_id = ?
                """,
                (
                    ExecutionClaimStatus.RELEASED.value,
                    released_at.isoformat(),
                    reason,
                    claim_id,
                ),
            )

        updated = self.get_by_permit(
            claim.permit_id
        )

        if updated is None:
            raise ExecutionClaimError(
                "Released execution claim disappeared."
            )

        return updated
