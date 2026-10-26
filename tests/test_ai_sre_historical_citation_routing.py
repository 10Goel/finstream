"""Historical citation namespace repair tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from services.ai_sre_agent.memory import (
    HistoricalIncidentContext,
)
from services.ai_sre_agent.models import IncidentStatus
from services.ai_sre_agent.reasoning.constraints import (
    CandidateHypothesis,
    ReasoningConstraints,
)
from services.ai_sre_agent.reasoning.selector import (
    EvidenceConstrainedReasoner,
)


class SequencedProvider:
    """Return controlled model responses in order."""

    def __init__(self) -> None:
        self.calls = 0
        self.system_prompts: list[str] = []

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        del user_prompt

        self.calls += 1
        self.system_prompts.append(system_prompt)

        base_selection = {
            "candidate_id": (
                "processor-immediate-unavailable"
            ),
            "confidence": 0.90,
            "explanation": (
                "The current processor evidence supports "
                "the supplied candidate. A previous "
                "historical incident provides precedent."
            ),
            "historical_context_ids": [
                "hist-mem-processor-previous"
            ],
        }

        if self.calls == 1:
            # Reproduce the real-Qwen mistake:
            # correct historical citation PLUS the same historical
            # ID incorrectly placed in the documentation namespace.
            decision = {
                **base_selection,
                "documentation_context_ids": [
                    "hist-mem-processor-previous"
                ],
            }
        else:
            # Bounded repair must cause the model to use the proper
            # independent namespace.
            decision = {
                **base_selection,
                "documentation_context_ids": [],
            }

        return json.dumps(
            {
                "abstain": False,
                "selections": [decision],
                "abstention_reason": None,
            }
        )


def _constraints() -> ReasoningConstraints:
    return ReasoningConstraints(
        affected_service="processor",
        observed_conditions=(
            "processor_unavailable",
            "kafka_healthy",
            "postgres_healthy",
        ),
        ruled_out_subsystems=(
            "kafka",
            "postgres",
        ),
        candidates=(
            CandidateHypothesis(
                candidate_id=(
                    "processor-immediate-unavailable"
                ),
                statement=(
                    "FinStream processor workload is "
                    "unavailable; the deeper reason is "
                    "not established by current evidence."
                ),
                supporting_evidence=(
                    "ev-prometheus-current",
                    "ev-kubernetes-current",
                ),
                confidence_ceiling=0.99,
            ),
        ),
    )


def _history() -> HistoricalIncidentContext:
    return HistoricalIncidentContext(
        context_id="hist-mem-processor-previous",
        memory_id="mem-processor-previous",
        historical_incident_id=(
            "inc-processor-previous"
        ),
        alert_name="FinStreamServiceDown",
        severity="critical",
        affected_service="processor",
        historical_summary=(
            "Previous finalized processor outage."
        ),
        final_status=IncidentStatus.RESOLVED,
        resolution_summary=(
            "Previous incident recovered after separately "
            "authorized remediation."
        ),
        finalized_at=datetime(
            2026,
            10,
            20,
            12,
            0,
            tzinfo=UTC,
        ),
        selected_candidate_ids=(
            "processor-immediate-unavailable",
        ),
        runbook_ids=(
            "RB-PROCESSOR-001",
        ),
        retrieval_score=314,
        matched_terms=(
            "processor",
            "unavailable",
        ),
        retrieval_reasons=(
            "exact_alert_match",
            "affected_service_match",
        ),
    )


def test_cross_domain_historical_citation_gets_one_bounded_repair():
    provider = SequencedProvider()

    reasoner = EvidenceConstrainedReasoner(
        provider=provider
    )

    history = _history()

    result = reasoner.select(
        constraints=_constraints(),
        historical_context=(
            history,
        ),
    )

    assert provider.calls == 2

    assert len(result.selections) == 1

    selected = result.selections[0]

    assert (
        selected.candidate_id
        == "processor-immediate-unavailable"
    )

    assert selected.runbook_citations == ()

    assert (
        selected.supporting_evidence
        == (
            "ev-prometheus-current",
            "ev-kubernetes-current",
        )
    )

    assert len(
        selected.historical_incident_citations
    ) == 1

    citation = (
        selected.historical_incident_citations[0]
    )

    assert (
        citation.context_id
        == history.context_id
    )

    assert (
        citation.memory_id
        == history.memory_id
    )

    assert (
        citation.historical_incident_id
        == history.historical_incident_id
    )

    repair_prompt = provider.system_prompts[1]

    assert (
        "CITATION NAMESPACE ERROR"
        in repair_prompt
    )

    assert (
        "hist-mem-processor-previous"
        in repair_prompt
    )


def test_cross_domain_repair_remains_fail_closed():
    class AlwaysWrongProvider:
        def generate(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
        ) -> str:
            del system_prompt
            del user_prompt

            return json.dumps(
                {
                    "abstain": False,
                    "selections": [
                        {
                            "candidate_id": (
                                "processor-"
                                "immediate-unavailable"
                            ),
                            "confidence": 0.90,
                            "explanation": (
                                "Historical precedent "
                                "supports this candidate."
                            ),
                            "documentation_context_ids": [
                                (
                                    "hist-mem-"
                                    "processor-previous"
                                )
                            ],
                            "historical_context_ids": [
                                (
                                    "hist-mem-"
                                    "processor-previous"
                                )
                            ],
                        }
                    ],
                    "abstention_reason": None,
                }
            )

    from services.ai_sre_agent.reasoning.selector import (
        CandidateSelectionOutputError,
    )

    reasoner = EvidenceConstrainedReasoner(
        provider=AlwaysWrongProvider()
    )

    try:
        reasoner.select(
            constraints=_constraints(),
            historical_context=(
                _history(),
            ),
        )
    except CandidateSelectionOutputError as exc:
        assert (
            "citation namespaces"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Repeated cross-domain citations were accepted."
        )
