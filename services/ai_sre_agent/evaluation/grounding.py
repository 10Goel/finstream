"""Evaluation contracts for FinStream multi-source AI grounding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GroundingMode(str, Enum):
    """Reference context channels available during evaluation."""

    CURRENT_ONLY = "CURRENT_ONLY"

    CURRENT_PLUS_RUNBOOKS = (
        "CURRENT_PLUS_RUNBOOKS"
    )

    CURRENT_PLUS_HISTORY = (
        "CURRENT_PLUS_HISTORY"
    )

    CURRENT_PLUS_RUNBOOKS_AND_HISTORY = (
        "CURRENT_PLUS_RUNBOOKS_AND_HISTORY"
    )

    @property
    def uses_runbooks(self) -> bool:
        """Return whether runbook RAG is enabled."""
        return self in {
            GroundingMode.CURRENT_PLUS_RUNBOOKS,
            GroundingMode.CURRENT_PLUS_RUNBOOKS_AND_HISTORY,
        }

    @property
    def uses_history(self) -> bool:
        """Return whether historical memory is enabled."""
        return self in {
            GroundingMode.CURRENT_PLUS_HISTORY,
            GroundingMode.CURRENT_PLUS_RUNBOOKS_AND_HISTORY,
        }


@dataclass(frozen=True, slots=True)
class GroundingExpectation:
    """Expected retrieval behavior for one grounding scenario."""

    expected_runbook_top1_id: str | None = None
    expected_historical_top1_incident_id: str | None = None

    def validate_mode(
        self,
        *,
        mode: GroundingMode,
    ) -> None:
        """Ensure expectations agree with enabled context channels."""
        if (
            self.expected_runbook_top1_id is not None
            and not mode.uses_runbooks
        ):
            raise ValueError(
                "Runbook retrieval expectation requires "
                "a runbook-enabled grounding mode."
            )

        if (
            self.expected_historical_top1_incident_id
            is not None
            and not mode.uses_history
        ):
            raise ValueError(
                "Historical retrieval expectation requires "
                "a history-enabled grounding mode."
            )


@dataclass(frozen=True, slots=True)
class GroundingSecurityExpectation:
    """Security properties that every grounded run must preserve."""

    require_candidate_boundary: bool = True
    require_operational_evidence_boundary: bool = True
    require_documentation_citation_integrity: bool = True
    require_historical_citation_integrity: bool = True
    require_namespace_isolation: bool = True
