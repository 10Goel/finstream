"""Deterministic remediation policy for FinStream AI-SRE."""

from __future__ import annotations

from services.ai_sre_agent.models import Incident
from services.ai_sre_agent.reasoning.constraints import (
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    CandidateSelectionOutcome,
    SelectedCandidate,
)
from services.ai_sre_agent.remediation.models import (
    RemediationActionType,
    RemediationCandidate,
    RemediationPlanConstraints,
    RemediationRiskLevel,
)


class RemediationPolicyError(RuntimeError):
    """Invalid or unsafe input reached remediation planning."""


_CRITICAL_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "api": ("postgres",),
    "producer": ("kafka",),
    "processor": (
        "kafka",
        "postgres",
    ),
}


class RemediationPolicyPlanner:
    """Build only remediation actions allowed by deterministic policy."""

    @staticmethod
    def _normalize_service(
        service: str | None,
    ) -> str | None:
        if service is None:
            return None

        normalized = service.strip().casefold()

        aliases = {
            "postgresql": "postgres",
            "stream_processor": "processor",
            "stream-processor": "processor",
        }

        return aliases.get(
            normalized,
            normalized,
        )

    @staticmethod
    def _validate_selected_candidate(
        *,
        selected: SelectedCandidate,
        constraints: ReasoningConstraints,
    ) -> None:
        candidate_index = {
            candidate.candidate_id: candidate
            for candidate in constraints.candidates
        }

        candidate = candidate_index.get(
            selected.candidate_id
        )

        if candidate is None:
            raise RemediationPolicyError(
                "Selected diagnosis is outside the deterministic "
                "candidate set."
            )

        if selected.statement != candidate.statement:
            raise RemediationPolicyError(
                "Selected diagnosis statement differs from the "
                "deterministic candidate."
            )

        if (
            selected.supporting_evidence
            != candidate.supporting_evidence
        ):
            raise RemediationPolicyError(
                "Selected diagnosis supporting evidence differs "
                "from the deterministic candidate."
            )

        if (
            selected.contradicting_evidence
            != candidate.contradicting_evidence
        ):
            raise RemediationPolicyError(
                "Selected diagnosis contradicting evidence differs "
                "from the deterministic candidate."
            )

    @classmethod
    def build(
        cls,
        *,
        incident: Incident,
        constraints: ReasoningConstraints,
        selection: CandidateSelectionOutcome,
    ) -> RemediationPlanConstraints:
        """Build an approval-aware remediation boundary."""
        affected_service = cls._normalize_service(
            incident.affected_service
        )

        if affected_service is None:
            raise RemediationPolicyError(
                "Incident affected_service is required."
            )

        if affected_service != constraints.affected_service:
            raise RemediationPolicyError(
                "Incident service does not match reasoning constraints."
            )

        if selection.abstained:
            return RemediationPlanConstraints(
                incident_id=incident.incident_id,
                affected_service=affected_service,
                diagnosis_candidate_id=None,
                candidates=(),
                blocked_reason=(
                    "Remediation blocked because the diagnostic "
                    "reasoner abstained."
                ),
            )

        if len(selection.selections) != 1:
            return RemediationPlanConstraints(
                incident_id=incident.incident_id,
                affected_service=affected_service,
                diagnosis_candidate_id=None,
                candidates=(),
                blocked_reason=(
                    "Remediation requires exactly one supported "
                    "diagnostic candidate."
                ),
            )

        selected = selection.selections[0]

        cls._validate_selected_candidate(
            selected=selected,
            constraints=constraints,
        )

        expected_candidate_id = (
            f"{affected_service}-immediate-unavailable"
        )

        if selected.candidate_id != expected_candidate_id:
            return RemediationPlanConstraints(
                incident_id=incident.incident_id,
                affected_service=affected_service,
                diagnosis_candidate_id=(
                    selected.candidate_id
                ),
                candidates=(),
                blocked_reason=(
                    "Selected diagnosis has no approved remediation "
                    "policy."
                ),
            )

        required_dependencies = _CRITICAL_DEPENDENCIES.get(
            affected_service
        )

        if required_dependencies is None:
            return RemediationPlanConstraints(
                incident_id=incident.incident_id,
                affected_service=affected_service,
                diagnosis_candidate_id=selected.candidate_id,
                candidates=(),
                blocked_reason=(
                    "Affected service has no deterministic "
                    "remediation policy."
                ),
            )

        ruled_out = set(
            constraints.ruled_out_subsystems
        )

        unresolved_dependencies = tuple(
            dependency
            for dependency in required_dependencies
            if dependency not in ruled_out
        )

        if unresolved_dependencies:
            dependency_text = ", ".join(
                unresolved_dependencies
            )

            candidate = RemediationCandidate(
                action_id=(
                    f"{affected_service}-"
                    "dependency-investigation"
                ),
                action_type=(
                    RemediationActionType.INVESTIGATE_DEPENDENCIES
                ),
                affected_service=affected_service,
                description=(
                    "Investigate unresolved service dependencies "
                    "before permitting a mutating recovery action."
                ),
                rationale=(
                    "The affected workload is unavailable, but "
                    f"these critical dependencies are not ruled "
                    f"out as contributors: {dependency_text}."
                ),
                risk_level=RemediationRiskLevel.LOW,
                requires_approval=False,
                supporting_evidence=(
                    selected.supporting_evidence
                ),
                verification_steps=(
                    "Re-run direct dependency health diagnostics.",
                    (
                        "Confirm whether each critical dependency "
                        "is healthy or degraded."
                    ),
                    (
                        "Rebuild remediation constraints after new "
                        "evidence is collected."
                    ),
                ),
            )

            return RemediationPlanConstraints(
                incident_id=incident.incident_id,
                affected_service=affected_service,
                diagnosis_candidate_id=selected.candidate_id,
                candidates=(candidate,),
            )

        candidate = RemediationCandidate(
            action_id=(
                f"{affected_service}-rolling-restart"
            ),
            action_type=(
                RemediationActionType.ROLLING_RESTART
            ),
            affected_service=affected_service,
            description=(
                f"Perform an approval-gated rolling restart of "
                f"the FinStream {affected_service} workload."
            ),
            rationale=(
                "The workload is directly observed as unavailable "
                "and its critical dependencies have been ruled out "
                "as unhealthy contributors."
            ),
            risk_level=RemediationRiskLevel.MEDIUM,
            requires_approval=True,
            supporting_evidence=(
                selected.supporting_evidence
            ),
            verification_steps=(
                "Confirm the workload returns to a ready state.",
                "Confirm Prometheus reports the service target as up.",
                "Confirm the original incident symptoms recover.",
            ),
            rollback_guidance=(
                "If health degrades after execution, stop further "
                "automated progression and return the incident to "
                "investigation."
            ),
        )

        return RemediationPlanConstraints(
            incident_id=incident.incident_id,
            affected_service=affected_service,
            diagnosis_candidate_id=selected.candidate_id,
            candidates=(candidate,),
        )
