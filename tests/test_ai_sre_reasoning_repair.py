import json

import pytest

from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    Incident,
)
from services.ai_sre_agent.reasoning import (
    EvidenceGroundingError,
    EvidenceReasoningEngine,
    ModelProviderError,
    ReasoningError,
)


class SequenceProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )

        response = self.responses[
            len(self.calls) - 1
        ]

        if isinstance(response, Exception):
            raise response

        return response


def make_incident():
    return Incident(
        fingerprint="repair-test",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )


def make_evidence(incident):
    return [
        Evidence(
            incident_id=incident.incident_id,
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            summary=(
                "Processor deployment has zero "
                "ready replicas."
            ),
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="processor",
            metadata={
                "desired_replicas": 0,
                "ready_replicas": 0,
                "available_replicas": 0,
                "healthy": False,
            },
            evidence_id="ev-k8s",
        )
    ]


def valid_response():
    return json.dumps(
        {
            "hypotheses": [
                {
                    "statement": (
                        "Processor workload is unavailable; "
                        "the deeper reason is not established "
                        "by the supplied evidence."
                    ),
                    "confidence": 0.95,
                    "supporting_evidence": [
                        "ev-k8s",
                    ],
                    "contradicting_evidence": [],
                }
            ]
        }
    )


def duplicate_response():
    proposal = {
        "statement": "Processor workload is unavailable.",
        "confidence": 0.9,
        "supporting_evidence": [
            "ev-k8s",
        ],
        "contradicting_evidence": [],
    }

    return json.dumps(
        {
            "hypotheses": [
                proposal,
                proposal,
            ]
        }
    )


def test_valid_first_response_uses_one_model_call():
    incident = make_incident()
    evidence = make_evidence(incident)

    provider = SequenceProvider(
        [
            valid_response(),
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    result = engine.generate_hypotheses_with_repair(
        incident=incident,
        evidence=evidence,
    )

    assert len(result) == 1
    assert len(provider.calls) == 1


def test_invalid_first_response_is_repaired_once():
    incident = make_incident()
    evidence = make_evidence(incident)

    provider = SequenceProvider(
        [
            duplicate_response(),
            valid_response(),
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    result = engine.generate_hypotheses_with_repair(
        incident=incident,
        evidence=evidence,
    )

    assert len(result) == 1
    assert len(provider.calls) == 2

    repair_payload = json.loads(
        provider.calls[1]["user_prompt"]
    )

    assert (
        repair_payload["task"]
        == "repair_invalid_reasoning_response"
    )

    assert (
        "duplicate hypotheses"
        in repair_payload[
            "validation_error"
        ].lower()
    )


def test_bad_repair_fails_after_two_calls():
    incident = make_incident()
    evidence = make_evidence(incident)

    provider = SequenceProvider(
        [
            duplicate_response(),
            duplicate_response(),
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    with pytest.raises(
        EvidenceGroundingError,
        match="duplicate hypotheses",
    ):
        engine.generate_hypotheses_with_repair(
            incident=incident,
            evidence=evidence,
        )

    assert len(provider.calls) == 2


def test_provider_failure_is_not_retried():
    incident = make_incident()
    evidence = make_evidence(incident)

    provider = SequenceProvider(
        [
            ModelProviderError(
                "provider unavailable"
            ),
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    with pytest.raises(
        ReasoningError,
        match="Model provider failed",
    ):
        engine.generate_hypotheses_with_repair(
            incident=incident,
            evidence=evidence,
        )

    assert len(provider.calls) == 1


def test_repair_does_not_mutate_original_evidence():
    incident = make_incident()
    evidence = make_evidence(incident)

    before = [
        {
            "evidence_id": item.evidence_id,
            "summary": item.summary,
            "service": item.service,
            "metadata": dict(item.metadata),
        }
        for item in evidence
    ]

    provider = SequenceProvider(
        [
            duplicate_response(),
            valid_response(),
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    engine.generate_hypotheses_with_repair(
        incident=incident,
        evidence=evidence,
    )

    after = [
        {
            "evidence_id": item.evidence_id,
            "summary": item.summary,
            "service": item.service,
            "metadata": dict(item.metadata),
        }
        for item in evidence
    ]

    assert after == before


def test_repaired_response_still_passes_grounding_gate():
    incident = make_incident()
    evidence = make_evidence(incident)

    bad_repair = json.dumps(
        {
            "hypotheses": [
                {
                    "statement": (
                        "Processor workload is unavailable."
                    ),
                    "confidence": 0.9,
                    "supporting_evidence": [
                        "ev-invented",
                    ],
                    "contradicting_evidence": [],
                }
            ]
        }
    )

    provider = SequenceProvider(
        [
            duplicate_response(),
            bad_repair,
        ]
    )

    engine = EvidenceReasoningEngine(
        provider=provider,
    )

    with pytest.raises(
        EvidenceGroundingError,
    ):
        engine.generate_hypotheses_with_repair(
            incident=incident,
            evidence=evidence,
        )

    assert len(provider.calls) == 2
