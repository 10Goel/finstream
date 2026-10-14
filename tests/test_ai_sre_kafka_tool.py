from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from confluent_kafka import (
    ConsumerGroupTopicPartitions,
    TopicPartition,
)

from services.ai_sre_agent.models import (
    EvidenceSource,
    EvidenceTrustLevel,
)
from services.ai_sre_agent.tools.kafka import (
    KafkaDiagnosticError,
    KafkaDiagnosticTool,
)


class FakeFuture:
    def __init__(self, value):
        self._value = value

    def result(self, timeout=None):
        return self._value


def broker_metadata():
    return SimpleNamespace(
        brokers={
            1: SimpleNamespace(
                host="kafka",
                port=9092,
            )
        },
        topics={},
    )


def healthy_topic_metadata():
    partitions = {
        partition: SimpleNamespace(
            leader=1,
            replicas=[1],
            isrs=[1],
        )
        for partition in range(3)
    }

    return SimpleNamespace(
        brokers={
            1: SimpleNamespace(
                host="kafka",
                port=9092,
            )
        },
        topics={
            "transactions": SimpleNamespace(
                error=None,
                partitions=partitions,
            )
        },
    )


def make_tool(admin=None):
    admin = admin or MagicMock()

    return (
        KafkaDiagnosticTool(
            "kafka:9092",
            admin_client=admin,
        ),
        admin,
    )


def test_broker_health_returns_structured_evidence():
    tool, admin = make_tool()

    admin.list_topics.return_value = (
        broker_metadata()
    )

    evidence = tool.check_broker_health(
        incident_id="inc-test",
    )

    assert evidence.source is EvidenceSource.KAFKA
    assert (
        evidence.trust_level
        is EvidenceTrustLevel.DIRECT_OBSERVATION
    )
    assert evidence.service == "kafka"
    assert evidence.metadata["healthy"] is True
    assert evidence.metadata["broker_count"] == 1
    assert evidence.metadata["brokers"][0]["host"] == "kafka"


def test_topic_metadata_reports_three_healthy_partitions():
    tool, admin = make_tool()

    admin.list_topics.return_value = (
        healthy_topic_metadata()
    )

    evidence = tool.get_topic_metadata(
        incident_id="inc-test",
        topic="transactions",
    )

    assert evidence.metadata["exists"] is True
    assert evidence.metadata["partition_count"] == 3
    assert evidence.metadata["replication_factor"] == 1
    assert (
        evidence.metadata[
            "under_replicated_partitions"
        ]
        == 0
    )
    assert evidence.metadata["healthy"] is True


def test_topic_metadata_detects_under_replication():
    tool, admin = make_tool()

    admin.list_topics.return_value = (
        SimpleNamespace(
            brokers={},
            topics={
                "transactions": SimpleNamespace(
                    error=None,
                    partitions={
                        0: SimpleNamespace(
                            leader=1,
                            replicas=[1, 2],
                            isrs=[1],
                        )
                    },
                )
            },
        )
    )

    evidence = tool.get_topic_metadata(
        incident_id="inc-test",
        topic="transactions",
    )

    assert (
        evidence.metadata[
            "under_replicated_partitions"
        ]
        == 1
    )
    assert evidence.metadata["healthy"] is False


def test_missing_topic_returns_evidence():
    tool, admin = make_tool()

    admin.list_topics.return_value = (
        SimpleNamespace(
            brokers={},
            topics={},
        )
    )

    evidence = tool.get_topic_metadata(
        incident_id="inc-test",
        topic="transactions.dlq",
    )

    assert evidence.metadata["exists"] is False
    assert evidence.metadata["partition_count"] == 0


def test_consumer_group_state_reports_member():
    tool, admin = make_tool()

    member = SimpleNamespace(
        member_id="member-1",
        client_id="rdkafka",
        host="/10.244.0.11",
        assignment=SimpleNamespace(
            topic_partitions=[
                TopicPartition(
                    "transactions",
                    0,
                )
            ]
        ),
    )

    description = SimpleNamespace(
        state=SimpleNamespace(
            name="STABLE",
        ),
        members=[member],
    )

    admin.describe_consumer_groups.return_value = {
        "finstream-anomaly-detector": FakeFuture(
            description
        )
    }

    evidence = tool.get_consumer_group_state(
        incident_id="inc-test",
    )

    assert evidence.metadata["state"] == "STABLE"
    assert evidence.metadata["member_count"] == 1
    assert (
        evidence.metadata["members"][0][
            "client_id"
        ]
        == "rdkafka"
    )


def test_consumer_lag_is_calculated_per_partition():
    tool, admin = make_tool()

    committed = (
        ConsumerGroupTopicPartitions(
            "finstream-anomaly-detector",
            [
                TopicPartition(
                    "transactions",
                    0,
                    1,
                ),
                TopicPartition(
                    "transactions",
                    1,
                    22476,
                ),
                TopicPartition(
                    "transactions",
                    2,
                    1,
                ),
            ],
        )
    )

    admin.list_consumer_group_offsets.return_value = {
        "finstream-anomaly-detector": FakeFuture(
            committed
        )
    }

    def list_offsets(requests, **_kwargs):
        end_offsets = {
            0: 1,
            1: 22477,
            2: 1,
        }

        return {
            tp: FakeFuture(
                SimpleNamespace(
                    offset=end_offsets[
                        tp.partition
                    ]
                )
            )
            for tp in requests
        }

    admin.list_offsets.side_effect = list_offsets

    evidence = tool.get_consumer_lag(
        incident_id="inc-test",
    )

    assert evidence.metadata["partition_count"] == 3
    assert evidence.metadata["total_lag"] == 1
    assert evidence.metadata["unknown_offsets"] == 0

    lags = {
        item["partition"]: item["lag"]
        for item in evidence.metadata["partitions"]
    }

    assert lags == {
        0: 0,
        1: 1,
        2: 0,
    }


def test_missing_committed_offsets_returns_zero_lag():
    tool, admin = make_tool()

    committed = (
        ConsumerGroupTopicPartitions(
            "finstream-anomaly-detector",
            [],
        )
    )

    admin.list_consumer_group_offsets.return_value = {
        "finstream-anomaly-detector": FakeFuture(
            committed
        )
    }

    evidence = tool.get_consumer_lag(
        incident_id="inc-test",
    )

    assert evidence.metadata["partition_count"] == 0
    assert evidence.metadata["total_lag"] == 0

    admin.list_offsets.assert_not_called()


@pytest.mark.parametrize(
    "topic",
    [
        "random-topic",
        "__consumer_offsets",
    ],
)
def test_unapproved_topic_is_rejected(topic):
    tool, admin = make_tool()

    with pytest.raises(
        ValueError,
        match="Unsupported FinStream Kafka topic",
    ):
        tool.get_topic_metadata(
            incident_id="inc-test",
            topic=topic,
        )

    admin.list_topics.assert_not_called()


def test_unapproved_consumer_group_is_rejected():
    tool, admin = make_tool()

    with pytest.raises(
        ValueError,
        match="Unsupported FinStream consumer group",
    ):
        tool.get_consumer_group_state(
            incident_id="inc-test",
            group_id="random-group",
        )

    admin.describe_consumer_groups.assert_not_called()


def test_empty_bootstrap_servers_is_rejected():
    with pytest.raises(
        ValueError,
        match="bootstrap_servers must not be empty",
    ):
        KafkaDiagnosticTool(" ")


def test_non_positive_timeout_is_rejected():
    with pytest.raises(
        ValueError,
        match="timeout_seconds must be positive",
    ):
        KafkaDiagnosticTool(
            "kafka:9092",
            timeout_seconds=0,
        )


def test_admin_error_is_wrapped():
    tool, admin = make_tool()

    admin.list_topics.side_effect = RuntimeError(
        "broker unavailable"
    )

    with pytest.raises(
        KafkaDiagnosticError,
        match="Unable to retrieve Kafka cluster metadata",
    ):
        tool.check_broker_health(
            incident_id="inc-test",
        )
