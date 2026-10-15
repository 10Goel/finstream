import json

from services.ai_sre_agent.models import (
    AlertStatus,
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
    HypothesisStatus,
    Incident,
)
from services.ai_sre_agent.reasoning import (
    EvidenceReasoningEngine,
)


class DeterministicIncidentProvider:
    """Deterministic model stand-in for reasoning integration tests."""

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        payload = json.loads(user_prompt)

        evidence_by_tool = {
            item["tool"]: item["evidence_id"]
            for item in payload["evidence"]
        }

        return json.dumps(
            {
                "hypotheses": [
                    {
                        "statement": (
                            "The FinStream processor workload is "
                            "unavailable, causing its Kafka consumer "
                            "group to lose its active member and "
                            "transaction lag to accumulate."
                        ),
                        "confidence": 0.98,
                        "supporting_evidence": [
                            evidence_by_tool[
                                "get_service_health"
                            ],
                            evidence_by_tool[
                                "get_deployment_status"
                            ],
                            evidence_by_tool[
                                "get_pods"
                            ],
                            evidence_by_tool[
                                "get_consumer_group_state"
                            ],
                            evidence_by_tool[
                                "get_consumer_lag"
                            ],
                        ],
                        "contradicting_evidence": [],
                    },
                    {
                        "statement": (
                            "A Kafka broker failure caused the "
                            "processor outage."
                        ),
                        "confidence": 0.05,
                        "supporting_evidence": [
                            evidence_by_tool[
                                "get_consumer_lag"
                            ],
                        ],
                        "contradicting_evidence": [
                            evidence_by_tool[
                                "check_broker_health"
                            ],
                            evidence_by_tool[
                                "get_topic_metadata"
                            ],
                        ],
                    },
                ]
            }
        )


def make_evidence(
    incident: Incident,
    *,
    evidence_id: str,
    source: EvidenceSource,
    tool: str,
    summary: str,
    service: str,
) -> Evidence:
    return Evidence(
        incident_id=incident.incident_id,
        source=source,
        tool=tool,
        summary=summary,
        trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
        service=service,
        evidence_id=evidence_id,
    )


def test_realistic_processor_outage_produces_grounded_hypotheses():
    incident = Incident(
        fingerprint="m10-7-processor-outage-replay",
        alert_name="FinStreamServiceDown",
        alert_status=AlertStatus.FIRING,
        severity="critical",
        affected_service="processor",
        summary="FinStream processor became unavailable.",
    )

    evidence = [
        make_evidence(
            incident,
            evidence_id="ev-prometheus-health",
            source=EvidenceSource.PROMETHEUS,
            tool="get_service_health",
            summary=(
                "Prometheus reports 0 of 1 processor "
                "targets as up."
            ),
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-k8s-deployment",
            source=EvidenceSource.KUBERNETES,
            tool="get_deployment_status",
            summary=(
                "Processor deployment is not fully available: "
                "desired=0, ready=0, available=0."
            ),
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-k8s-pods",
            source=EvidenceSource.KUBERNETES,
            tool="get_pods",
            summary="No Kubernetes pods found for processor.",
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-logs",
            source=EvidenceSource.LOGS,
            tool="get_recent_logs",
            summary=(
                "No Kubernetes pod found for processor; "
                "no logs collected."
            ),
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-kafka-broker",
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            summary="Kafka reports 1 reachable broker.",
            service="kafka",
        ),
        make_evidence(
            incident,
            evidence_id="ev-kafka-topic",
            source=EvidenceSource.KAFKA,
            tool="get_topic_metadata",
            summary=(
                "Kafka topic transactions has 3 partitions "
                "and 0 under-replicated partitions."
            ),
            service="kafka",
        ),
        make_evidence(
            incident,
            evidence_id="ev-kafka-group",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_group_state",
            summary=(
                "Kafka consumer group "
                "finstream-anomaly-detector is EMPTY "
                "with 0 members."
            ),
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-kafka-lag",
            source=EvidenceSource.KAFKA,
            tool="get_consumer_lag",
            summary=(
                "Kafka consumer group has accumulated "
                "transaction lag while the processor "
                "is unavailable."
            ),
            service="processor",
        ),
        make_evidence(
            incident,
            evidence_id="ev-postgres-health",
            source=EvidenceSource.POSTGRESQL,
            tool="check_database_health",
            summary=(
                "PostgreSQL database finstream is reachable "
                "using the read-only diagnostic identity."
            ),
            service="postgres",
        ),
    ]

    engine = EvidenceReasoningEngine(
        provider=DeterministicIncidentProvider(),
    )

    hypotheses = engine.generate_hypotheses(
        incident=incident,
        evidence=evidence,
    )

    assert len(hypotheses) == 2

    primary = hypotheses[0]

    assert primary.status is HypothesisStatus.PROPOSED
    assert primary.incident_id == incident.incident_id
    assert primary.confidence == 0.98

    assert primary.supporting_evidence == [
        "ev-prometheus-health",
        "ev-k8s-deployment",
        "ev-k8s-pods",
        "ev-kafka-group",
        "ev-kafka-lag",
    ]

    assert primary.contradicting_evidence == []

    alternative = hypotheses[1]

    assert alternative.confidence == 0.05

    assert alternative.supporting_evidence == [
        "ev-kafka-lag",
    ]

    assert alternative.contradicting_evidence == [
        "ev-kafka-broker",
        "ev-kafka-topic",
    ]

    all_known_ids = {
        item.evidence_id
        for item in evidence
    }

    for hypothesis in hypotheses:
        assert set(
            hypothesis.supporting_evidence
        ).issubset(all_known_ids)

        assert set(
            hypothesis.contradicting_evidence
        ).issubset(all_known_ids)
