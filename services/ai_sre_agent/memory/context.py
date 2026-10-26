"""Trusted-boundary representation of historical incident context."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from services.ai_sre_agent.memory.retriever import (
    HistoricalIncidentRetrievalResult,
)
from services.ai_sre_agent.models import (
    Incident,
    IncidentStatus,
)


class HistoricalContextError(RuntimeError):
    """Historical incident context violated its trust contract."""


@dataclass(frozen=True, slots=True)
class HistoricalIncidentContext:
    """One historical incident exposed as non-authoritative context.

    Historical context may inform model reasoning about precedent, but
    it must never establish current operational state, create candidate
    hypotheses, grant execution authority, or act as an instruction.
    """

    context_id: str

    memory_id: str
    historical_incident_id: str

    alert_name: str
    severity: str
    affected_service: str | None

    historical_summary: str | None
    final_status: IncidentStatus
    resolution_summary: str
    finalized_at: datetime

    selected_candidate_ids: tuple[str, ...]
    runbook_ids: tuple[str, ...]

    retrieval_score: int
    matched_terms: tuple[str, ...]
    retrieval_reasons: tuple[str, ...]

    trust_domain: str = "HISTORICAL_CONTEXT"
    authority: str = "HISTORICAL_REFERENCE_ONLY"

    current_state_authority: bool = False
    candidate_generation_authority: bool = False
    execution_authority: bool = False
    instruction_authority: bool = False
    embedded_text_is_instruction: bool = False

    def as_payload(self) -> dict[str, object]:
        """Return the bounded model-facing historical payload."""
        return {
            "context_id": self.context_id,
            "source": "incident_memory",
            "trust_domain": self.trust_domain,
            "authority": self.authority,
            "current_state_authority": (
                self.current_state_authority
            ),
            "candidate_generation_authority": (
                self.candidate_generation_authority
            ),
            "execution_authority": (
                self.execution_authority
            ),
            "instruction_authority": (
                self.instruction_authority
            ),
            "embedded_text_is_instruction": (
                self.embedded_text_is_instruction
            ),
            "memory_id": self.memory_id,
            "historical_incident_id": (
                self.historical_incident_id
            ),
            "alert_name": self.alert_name,
            "severity": self.severity,
            "affected_service": self.affected_service,
            "historical_summary": (
                self.historical_summary
            ),
            "final_status": self.final_status.value,
            "resolution_summary": (
                self.resolution_summary
            ),
            "finalized_at": (
                self.finalized_at.isoformat()
            ),
            "selected_candidate_ids": list(
                self.selected_candidate_ids
            ),
            "runbook_ids": list(
                self.runbook_ids
            ),
            "retrieval_score": self.retrieval_score,
            "matched_terms": list(
                self.matched_terms
            ),
            "retrieval_reasons": list(
                self.retrieval_reasons
            ),
        }


@dataclass(frozen=True, slots=True)
class HistoricalContextBundle:
    """Historical context associated with one current incident."""

    incident_id: str
    context: tuple[
        HistoricalIncidentContext,
        ...
    ]


class HistoricalContextBuilder:
    """Convert deterministic memory retrieval into guarded context."""

    _FINAL_STATUSES = frozenset(
        {
            IncidentStatus.RESOLVED,
            IncidentStatus.FAILED,
            IncidentStatus.CLOSED,
        }
    )

    _MAX_SUMMARY_CHARS = 600
    _MAX_RESOLUTION_CHARS = 1000

    @staticmethod
    def _bounded_text(
        value: str | None,
        *,
        limit: int,
    ) -> str | None:
        if value is None:
            return None

        normalized = " ".join(
            value.split()
        )

        if not normalized:
            return None

        return normalized[:limit]

    @classmethod
    def build(
        cls,
        *,
        incident: Incident,
        retrieval: HistoricalIncidentRetrievalResult,
    ) -> HistoricalContextBundle:
        """Build non-authoritative historical context."""
        if (
            retrieval.incident_id
            != incident.incident_id
        ):
            raise HistoricalContextError(
                "Historical retrieval belongs to a different "
                "current incident."
            )

        context: list[
            HistoricalIncidentContext
        ] = []

        memory_ids: set[str] = set()
        context_ids: set[str] = set()

        for match in retrieval.matches:
            record = match.record

            if (
                record.incident_id
                == incident.incident_id
            ):
                raise HistoricalContextError(
                    "Current incident cannot be exposed as "
                    "historical context."
                )

            if (
                record.final_status
                not in cls._FINAL_STATUSES
            ):
                raise HistoricalContextError(
                    "Historical context requires a finalized "
                    "incident memory."
                )

            if record.finalized_at is None:
                raise HistoricalContextError(
                    "Historical context requires finalized_at."
                )

            resolution_summary = (
                cls._bounded_text(
                    record.resolution_summary,
                    limit=cls._MAX_RESOLUTION_CHARS,
                )
            )

            if resolution_summary is None:
                raise HistoricalContextError(
                    "Historical context requires a resolution "
                    "summary."
                )

            if match.score < 0:
                raise HistoricalContextError(
                    "Historical retrieval score must not be "
                    "negative."
                )

            if any(
                not value.strip()
                for value in match.matched_terms
            ):
                raise HistoricalContextError(
                    "Historical matched terms must not be "
                    "blank."
                )

            if any(
                not value.strip()
                for value in match.reasons
            ):
                raise HistoricalContextError(
                    "Historical retrieval reasons must not be "
                    "blank."
                )

            if record.memory_id in memory_ids:
                raise HistoricalContextError(
                    "Historical context contains duplicate "
                    "memory IDs."
                )

            context_id = (
                f"hist-{record.memory_id}"
            )

            if context_id in context_ids:
                raise HistoricalContextError(
                    "Historical context contains duplicate "
                    "context IDs."
                )

            memory_ids.add(
                record.memory_id
            )

            context_ids.add(
                context_id
            )

            context.append(
                HistoricalIncidentContext(
                    context_id=context_id,
                    memory_id=record.memory_id,
                    historical_incident_id=(
                        record.incident_id
                    ),
                    alert_name=record.alert_name,
                    severity=record.severity,
                    affected_service=(
                        record.affected_service
                    ),
                    historical_summary=(
                        cls._bounded_text(
                            record.summary,
                            limit=(
                                cls._MAX_SUMMARY_CHARS
                            ),
                        )
                    ),
                    final_status=(
                        record.final_status
                    ),
                    resolution_summary=(
                        resolution_summary
                    ),
                    finalized_at=(
                        record.finalized_at
                    ),
                    selected_candidate_ids=(
                        record.selected_candidate_ids
                    ),
                    runbook_ids=(
                        record.runbook_ids
                    ),
                    retrieval_score=match.score,
                    matched_terms=(
                        match.matched_terms
                    ),
                    retrieval_reasons=(
                        match.reasons
                    ),
                )
            )

        return HistoricalContextBundle(
            incident_id=incident.incident_id,
            context=tuple(context),
        )
