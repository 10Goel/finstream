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
)


class StaticProvider:
    def __init__(
        self,
        hypotheses,
    ):
        self._hypotheses = hypotheses

    def generate(
        self,
        *,
        system_prompt,
        user_prompt,
    ):
        assert system_prompt
        assert user_prompt

        return json.dumps(
            {
                "hypotheses": self._hypotheses,
            }
        )


def make_incident():
    return Incident(
        fingerprint="quality-test",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="Processor unavailable.",
    )


def make_evidence(
    incident,
    *,
    evidence_id,
    source,
    tool,
    summary,
    service,
    metadata=None,
):
    return Evidence(
        incident_id=incident.incident_id,
        source=source,
        tool=tool,
        summary=summary,
        trust_level=(
            EvidenceTrustLevel.DIRECT_OBSERVATION
        ),
        service=service,
        metadata=metadata or {},
        evidence_id=evidence_id,
    )


def run_reasoning(
    *,
    incident,
    evidence,
    hypotheses,
):
    engine = EvidenceReasoningEngine(
        provider=StaticProvider(
            hypotheses,
        )
    )

    return engine.generate_hypotheses(
        incident=incident,
        evidence=evidence,
    )


def test_duplicate_hypotheses_are_rejected():
    incident = make_incident()

    deployment = make_evidence(
        incident,
        evidence_id="ev-k8s",
        source=EvidenceSource.KUBERNETES,
        tool="get_deployment_status",
        summary="Processor has zero ready replicas.",
        service="processor",
        metadata={
            "healthy": False,
        },
    )

    proposal = {
        "statement": (
            "Processor workload is unavailable."
        ),
        "confidence": 0.9,
        "supporting_evidence": [
            "ev-k8s",
        ],
        "contradicting_evidence": [],
    }

    with pytest.raises(
        EvidenceGroundingError,
        match="duplicate hypotheses",
    ):
        run_reasoning(
            incident=incident,
            evidence=[
                deployment,
            ],
            hypotheses=[
                proposal,
                proposal,
            ],
        )


def test_state_observations_cannot_prove_deeper_cause():
    incident = make_incident()

    deployment = make_evidence(
        incident,
        evidence_id="ev-k8s",
        source=EvidenceSource.KUBERNETES,
        tool="get_deployment_status",
        summary=(
            "Processor deployment has desired=0, "
            "ready=0, available=0."
        ),
        service="processor",
        metadata={
            "healthy": False,
        },
    )

    with pytest.raises(
        EvidenceGroundingError,
        match="causal claim",
    ):
        run_reasoning(
            incident=incident,
            evidence=[
                deployment,
            ],
            hypotheses=[
                {
                    "statement": (
                        "Processor became unavailable "
                        "due to a failed Kubernetes "
                        "deployment."
                    ),
                    "confidence": 0.8,
                    "supporting_evidence": [
                        "ev-k8s",
                    ],
                    "contradicting_evidence": [],
                }
            ],
        )


def test_healthy_subsystem_cannot_support_blame():
    incident = make_incident()

    kafka = make_evidence(
        incident,
        evidence_id="ev-kafka",
        source=EvidenceSource.KAFKA,
        tool="check_broker_health",
        summary="Kafka broker is healthy.",
        service="kafka",
        metadata={
            "healthy": True,
        },
    )

    with pytest.raises(
        EvidenceGroundingError,
        match="Healthy evidence cannot support",
    ):
        run_reasoning(
            incident=incident,
            evidence=[
                kafka,
            ],
            hypotheses=[
                {
                    "statement": (
                        "Kafka failure caused "
                        "processor unavailability."
                    ),
                    "confidence": 0.7,
                    "supporting_evidence": [
                        "ev-kafka",
                    ],
                    "contradicting_evidence": [],
                }
            ],
        )


def test_unrelated_healthy_contradiction_is_rejected():
    incident = make_incident()

    deployment = make_evidence(
        incident,
        evidence_id="ev-k8s",
        source=EvidenceSource.KUBERNETES,
        tool="get_deployment_status",
        summary="Processor has zero ready replicas.",
        service="processor",
        metadata={
            "healthy": False,
        },
    )

    postgres = make_evidence(
        incident,
        evidence_id="ev-postgres",
        source=EvidenceSource.POSTGRESQL,
        tool="check_database_health",
        summary="PostgreSQL is healthy.",
        service="postgres",
        metadata={
            "healthy": True,
        },
    )

    with pytest.raises(
        EvidenceGroundingError,
        match="unrelated",
    ):
        run_reasoning(
            incident=incident,
            evidence=[
                deployment,
                postgres,
            ],
            hypotheses=[
                {
                    "statement": (
                        "Processor workload is "
                        "unavailable."
                    ),
                    "confidence": 0.9,
                    "supporting_evidence": [
                        "ev-k8s",
                    ],
                    "contradicting_evidence": [
                        "ev-postgres",
                    ],
                }
            ],
        )


def test_immediate_failure_state_is_accepted():
    incident = make_incident()

    deployment = make_evidence(
        incident,
        evidence_id="ev-k8s",
        source=EvidenceSource.KUBERNETES,
        tool="get_deployment_status",
        summary=(
            "Processor deployment has desired=0, "
            "ready=0, available=0."
        ),
        service="processor",
        metadata={
            "healthy": False,
        },
    )

    prometheus = make_evidence(
        incident,
        evidence_id="ev-prometheus",
        source=EvidenceSource.PROMETHEUS,
        tool="get_service_health",
        summary=(
            "Prometheus reports processor down."
        ),
        service="processor",
        metadata={
            "healthy": False,
            "up_targets": 0,
            "down_targets": 1,
        },
    )

    hypotheses = run_reasoning(
        incident=incident,
        evidence=[
            deployment,
            prometheus,
        ],
        hypotheses=[
            {
                "statement": (
                    "Processor workload is unavailable; "
                    "the deeper reason is not established "
                    "by the supplied evidence."
                ),
                "confidence": 0.95,
                "supporting_evidence": [
                    "ev-k8s",
                    "ev-prometheus",
                ],
                "contradicting_evidence": [],
            }
        ],
    )

    assert len(hypotheses) == 1

    assert (
        hypotheses[0].supporting_evidence
        == [
            "ev-k8s",
            "ev-prometheus",
        ]
    )
