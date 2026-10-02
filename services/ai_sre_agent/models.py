"""Domain models for the FinStream AI-SRE subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    """Generate a readable unique identifier for a domain object."""
    return f"{prefix}-{uuid4().hex}"


class IncidentStatus(str, Enum):
    """Lifecycle states for an AI-SRE incident."""

    RECEIVED = "RECEIVED"
    INVESTIGATING = "INVESTIGATING"
    DIAGNOSED = "DIAGNOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    CLOSED = "CLOSED"


class AlertStatus(str, Enum):
    """Normalized Alertmanager alert states."""

    FIRING = "firing"
    RESOLVED = "resolved"


class EvidenceSource(str, Enum):
    """Systems from which operational evidence may originate."""

    PROMETHEUS = "prometheus"
    KUBERNETES = "kubernetes"
    LOGS = "logs"
    KAFKA = "kafka"
    POSTGRESQL = "postgresql"
    GIT = "git"
    RUNBOOK = "runbook"


class EvidenceTrustLevel(str, Enum):
    """Semantic trust category assigned to an evidence item."""

    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    DERIVED_OBSERVATION = "DERIVED_OBSERVATION"
    DOCUMENTATION_CONTEXT = "DOCUMENTATION_CONTEXT"
    MODEL_INTERPRETATION = "MODEL_INTERPRETATION"


class ToolCallStatus(str, Enum):
    """Execution states for diagnostic tool calls."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    REJECTED = "REJECTED"


class HypothesisStatus(str, Enum):
    """Investigation states for competing hypotheses."""

    PROPOSED = "PROPOSED"
    INVESTIGATING = "INVESTIGATING"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"


_ALLOWED_INCIDENT_TRANSITIONS: dict[
    IncidentStatus,
    set[IncidentStatus],
] = {
    IncidentStatus.RECEIVED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FAILED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.DIAGNOSED,
        IncidentStatus.FAILED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.DIAGNOSED: {
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.AWAITING_APPROVAL: {
        IncidentStatus.REMEDIATING,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.REMEDIATING: {
        IncidentStatus.VERIFYING,
        IncidentStatus.FAILED,
    },
    IncidentStatus.VERIFYING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FAILED,
    },
    IncidentStatus.RESOLVED: set(),
    IncidentStatus.FAILED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.CLOSED: set(),
}


@dataclass(slots=True)
class Incident:
    """Normalized operational incident tracked by FinStream AI-SRE."""

    fingerprint: str
    alert_name: str
    alert_status: AlertStatus
    severity: str
    affected_service: str | None = None
    instance: str | None = None
    summary: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    resolved_at: datetime | None = None
    status: IncidentStatus = IncidentStatus.RECEIVED
    incident_id: str = field(default_factory=lambda: new_id("inc"))

    def transition_to(self, new_status: IncidentStatus) -> None:
        """Move the incident to a valid lifecycle state."""
        allowed = _ALLOWED_INCIDENT_TRANSITIONS[self.status]

        if new_status not in allowed:
            raise ValueError(
                f"Invalid incident transition: "
                f"{self.status.value} -> {new_status.value}"
            )

        self.status = new_status

        if new_status is IncidentStatus.RESOLVED and self.resolved_at is None:
            self.resolved_at = utc_now()


@dataclass(slots=True)
class Evidence:
    """Structured operational evidence collected during an investigation."""

    incident_id: str
    source: EvidenceSource
    tool: str
    summary: str
    trust_level: EvidenceTrustLevel
    service: str | None = None
    raw_reference: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=utc_now)
    evidence_id: str = field(default_factory=lambda: new_id("ev"))

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ValueError("Evidence summary must not be empty.")


@dataclass(slots=True)
class ToolCall:
    """Recorded invocation of an approved diagnostic tool."""

    incident_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    status: ToolCallStatus = ToolCallStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    evidence_ids: list[str] = field(default_factory=list)
    error: str | None = None
    tool_call_id: str = field(default_factory=lambda: new_id("tool"))


@dataclass(slots=True)
class Hypothesis:
    """A candidate explanation being evaluated against evidence."""

    incident_id: str
    statement: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float | None = None
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    hypothesis_id: str = field(default_factory=lambda: new_id("hyp"))

    def __post_init__(self) -> None:
        if not self.statement.strip():
            raise ValueError("Hypothesis statement must not be empty.")

        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Hypothesis confidence must be between 0 and 1.")


@dataclass(slots=True)
class RootCauseAnalysis:
    """Evidence-grounded root-cause analysis for an incident."""

    incident_id: str
    affected_service: str
    root_cause: str
    impact: str
    recommended_action: str
    supporting_evidence: list[str]
    confidence: float | None = None
    alternatives_considered: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    rca_id: str = field(default_factory=lambda: new_id("rca"))

    def __post_init__(self) -> None:
        if not self.root_cause.strip():
            raise ValueError("Root cause must not be empty.")

        if not self.supporting_evidence:
            raise ValueError(
                "Root-cause analysis requires supporting evidence."
            )

        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("RCA confidence must be between 0 and 1.")
