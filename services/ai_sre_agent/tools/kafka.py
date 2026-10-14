"""Read-only Kafka diagnostics for FinStream AI-SRE."""

from __future__ import annotations

from typing import Any

from confluent_kafka import (
    ConsumerGroupTopicPartitions,
    TopicPartition,
)
from confluent_kafka.admin import AdminClient, OffsetSpec

from services.ai_sre_agent.models import (
    Evidence,
    EvidenceSource,
    EvidenceTrustLevel,
)


class KafkaDiagnosticError(RuntimeError):
    """Raised when Kafka diagnostics cannot be completed."""


_ALLOWED_TOPICS = {
    "transactions",
    "transactions.dlq",
}

_ALLOWED_GROUPS = {
    "finstream-anomaly-detector",
}


class KafkaDiagnosticTool:
    """Bounded read-only Kafka diagnostics for FinStream."""

    def __init__(
        self,
        bootstrap_servers: str,
        *,
        timeout_seconds: float = 5.0,
        admin_client: Any | None = None,
    ) -> None:
        normalized_servers = bootstrap_servers.strip()

        if not normalized_servers:
            raise ValueError(
                "Kafka bootstrap_servers must not be empty."
            )

        if timeout_seconds <= 0:
            raise ValueError(
                "Kafka timeout_seconds must be positive."
            )

        self._bootstrap_servers = normalized_servers
        self._timeout_seconds = timeout_seconds

        self._admin = admin_client or AdminClient(
            {
                "bootstrap.servers": normalized_servers,
                "socket.timeout.ms": int(
                    timeout_seconds * 1000
                ),
            }
        )

    @staticmethod
    def _normalize_topic(topic: str) -> str:
        normalized = topic.strip()

        if normalized not in _ALLOWED_TOPICS:
            allowed = ", ".join(sorted(_ALLOWED_TOPICS))

            raise ValueError(
                f"Unsupported FinStream Kafka topic '{topic}'. "
                f"Allowed topics: {allowed}."
            )

        return normalized

    @staticmethod
    def _normalize_group(group_id: str) -> str:
        normalized = group_id.strip()

        if normalized not in _ALLOWED_GROUPS:
            allowed = ", ".join(sorted(_ALLOWED_GROUPS))

            raise ValueError(
                f"Unsupported FinStream consumer group "
                f"'{group_id}'. Allowed groups: {allowed}."
            )

        return normalized

    def _future_result(
        self,
        future: Any,
        operation: str,
    ) -> Any:
        try:
            return future.result(
                timeout=self._timeout_seconds,
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                f"Kafka operation failed: {operation}."
            ) from exc

    def check_broker_health(
        self,
        *,
        incident_id: str,
    ) -> Evidence:
        """Collect Kafka broker reachability evidence."""
        try:
            metadata = self._admin.list_topics(
                timeout=self._timeout_seconds,
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                "Unable to retrieve Kafka cluster metadata."
            ) from exc

        brokers = getattr(
            metadata,
            "brokers",
            {},
        ) or {}

        broker_details = []

        for broker_id, broker in sorted(
            brokers.items(),
            key=lambda item: item[0],
        ):
            broker_details.append(
                {
                    "id": int(broker_id),
                    "host": getattr(
                        broker,
                        "host",
                        None,
                    ),
                    "port": getattr(
                        broker,
                        "port",
                        None,
                    ),
                }
            )

        healthy = bool(broker_details)

        if healthy:
            summary = (
                f"Kafka metadata reports "
                f"{len(broker_details)} reachable broker(s)."
            )
        else:
            summary = (
                "Kafka metadata returned no reachable brokers."
            )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KAFKA,
            tool="check_broker_health",
            summary=summary,
            trust_level=EvidenceTrustLevel.DIRECT_OBSERVATION,
            service="kafka",
            raw_reference=(
                f"kafka metadata bootstrap="
                f"{self._bootstrap_servers}"
            ),
            metadata={
                "broker_count": len(broker_details),
                "brokers": broker_details,
                "healthy": healthy,
            },
        )

    def get_topic_metadata(
        self,
        *,
        incident_id: str,
        topic: str,
    ) -> Evidence:
        """Collect bounded metadata for an approved FinStream topic."""
        normalized_topic = self._normalize_topic(topic)

        try:
            metadata = self._admin.list_topics(
                topic=normalized_topic,
                timeout=self._timeout_seconds,
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                f"Unable to retrieve Kafka topic "
                f"metadata for '{normalized_topic}'."
            ) from exc

        topics = getattr(
            metadata,
            "topics",
            {},
        ) or {}

        topic_metadata = topics.get(
            normalized_topic
        )

        if topic_metadata is None:
            return Evidence(
                incident_id=incident_id,
                source=EvidenceSource.KAFKA,
                tool="get_topic_metadata",
                summary=(
                    f"Kafka topic {normalized_topic} "
                    f"was not found."
                ),
                trust_level=(
                    EvidenceTrustLevel.DIRECT_OBSERVATION
                ),
                service="kafka",
                raw_reference=(
                    f"topic={normalized_topic}"
                ),
                metadata={
                    "topic": normalized_topic,
                    "exists": False,
                    "partition_count": 0,
                    "under_replicated_partitions": 0,
                    "partitions": [],
                },
            )

        topic_error = getattr(
            topic_metadata,
            "error",
            None,
        )

        if topic_error is not None:
            raise KafkaDiagnosticError(
                f"Kafka returned an error for topic "
                f"'{normalized_topic}': {topic_error}"
            )

        partitions_metadata = getattr(
            topic_metadata,
            "partitions",
            {},
        ) or {}

        partitions = []
        under_replicated = 0
        unavailable_leaders = 0

        for partition_id, partition in sorted(
            partitions_metadata.items(),
            key=lambda item: item[0],
        ):
            replicas = list(
                getattr(
                    partition,
                    "replicas",
                    [],
                )
                or []
            )

            isrs = list(
                getattr(
                    partition,
                    "isrs",
                    [],
                )
                or []
            )

            leader = getattr(
                partition,
                "leader",
                -1,
            )

            is_under_replicated = (
                len(isrs) < len(replicas)
            )

            leader_available = (
                leader is not None
                and int(leader) >= 0
            )

            if is_under_replicated:
                under_replicated += 1

            if not leader_available:
                unavailable_leaders += 1

            partitions.append(
                {
                    "partition": int(partition_id),
                    "leader": (
                        int(leader)
                        if leader is not None
                        else None
                    ),
                    "replicas": [
                        int(replica)
                        for replica in replicas
                    ],
                    "isrs": [
                        int(replica)
                        for replica in isrs
                    ],
                    "under_replicated": (
                        is_under_replicated
                    ),
                    "leader_available": (
                        leader_available
                    ),
                }
            )

        partition_count = len(partitions)

        replication_factor = (
            len(partitions[0]["replicas"])
            if partitions
            else 0
        )

        healthy = (
            partition_count > 0
            and under_replicated == 0
            and unavailable_leaders == 0
        )

        summary = (
            f"Kafka topic {normalized_topic} has "
            f"{partition_count} partition(s), "
            f"replication factor {replication_factor}, "
            f"and {under_replicated} "
            f"under-replicated partition(s)."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KAFKA,
            tool="get_topic_metadata",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="kafka",
            raw_reference=(
                f"topic={normalized_topic}"
            ),
            metadata={
                "topic": normalized_topic,
                "exists": True,
                "partition_count": partition_count,
                "replication_factor": replication_factor,
                "under_replicated_partitions": (
                    under_replicated
                ),
                "unavailable_leaders": (
                    unavailable_leaders
                ),
                "healthy": healthy,
                "partitions": partitions,
            },
        )

    def get_consumer_group_state(
        self,
        *,
        incident_id: str,
        group_id: str = "finstream-anomaly-detector",
    ) -> Evidence:
        """Collect state and membership for an approved group."""
        normalized_group = self._normalize_group(
            group_id
        )

        try:
            futures = (
                self._admin.describe_consumer_groups(
                    [normalized_group],
                    request_timeout=(
                        self._timeout_seconds
                    ),
                )
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                f"Unable to describe Kafka consumer "
                f"group '{normalized_group}'."
            ) from exc

        future = futures.get(normalized_group)

        if future is None:
            raise KafkaDiagnosticError(
                f"Kafka returned no description future "
                f"for consumer group "
                f"'{normalized_group}'."
            )

        description = self._future_result(
            future,
            "describe consumer group",
        )

        raw_state = getattr(
            description,
            "state",
            None,
        )

        state = getattr(
            raw_state,
            "name",
            str(raw_state),
        )

        members = []

        for member in (
            getattr(
                description,
                "members",
                [],
            )
            or []
        ):
            assignment = getattr(
                member,
                "assignment",
                None,
            )

            topic_partitions = getattr(
                assignment,
                "topic_partitions",
                [],
            ) or []

            assigned = [
                {
                    "topic": tp.topic,
                    "partition": tp.partition,
                }
                for tp in topic_partitions
            ]

            members.append(
                {
                    "member_id": getattr(
                        member,
                        "member_id",
                        None,
                    ),
                    "client_id": getattr(
                        member,
                        "client_id",
                        None,
                    ),
                    "host": getattr(
                        member,
                        "host",
                        None,
                    ),
                    "assigned_partitions": (
                        assigned
                    ),
                }
            )

        summary = (
            f"Kafka consumer group {normalized_group} "
            f"is {state} with {len(members)} "
            f"member(s)."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KAFKA,
            tool="get_consumer_group_state",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="processor",
            raw_reference=(
                f"consumer-group={normalized_group}"
            ),
            metadata={
                "group_id": normalized_group,
                "state": state,
                "member_count": len(members),
                "members": members,
            },
        )

    def get_consumer_lag(
        self,
        *,
        incident_id: str,
        group_id: str = "finstream-anomaly-detector",
        topic: str = "transactions",
    ) -> Evidence:
        """Calculate committed-to-log-end lag for a consumer group."""
        normalized_group = self._normalize_group(
            group_id
        )
        normalized_topic = self._normalize_topic(
            topic
        )

        request = ConsumerGroupTopicPartitions(
            normalized_group
        )

        try:
            futures = (
                self._admin.list_consumer_group_offsets(
                    [request],
                    request_timeout=(
                        self._timeout_seconds
                    ),
                )
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                f"Unable to list committed offsets "
                f"for '{normalized_group}'."
            ) from exc

        future = futures.get(normalized_group)

        if future is None:
            raise KafkaDiagnosticError(
                f"Kafka returned no offset future "
                f"for consumer group "
                f"'{normalized_group}'."
            )

        group_offsets = self._future_result(
            future,
            "list consumer group offsets",
        )

        committed_partitions = [
            tp
            for tp in (
                getattr(
                    group_offsets,
                    "topic_partitions",
                    [],
                )
                or []
            )
            if tp.topic == normalized_topic
        ]

        if not committed_partitions:
            return Evidence(
                incident_id=incident_id,
                source=EvidenceSource.KAFKA,
                tool="get_consumer_lag",
                summary=(
                    f"No committed offsets found for "
                    f"{normalized_group} on "
                    f"{normalized_topic}."
                ),
                trust_level=(
                    EvidenceTrustLevel.DIRECT_OBSERVATION
                ),
                service="processor",
                raw_reference=(
                    f"consumer-group={normalized_group} "
                    f"topic={normalized_topic}"
                ),
                metadata={
                    "group_id": normalized_group,
                    "topic": normalized_topic,
                    "partition_count": 0,
                    "total_lag": 0,
                    "unknown_offsets": 0,
                    "partitions": [],
                },
            )

        latest_requests = {
            TopicPartition(
                tp.topic,
                tp.partition,
            ): OffsetSpec.latest()
            for tp in committed_partitions
        }

        try:
            latest_futures = (
                self._admin.list_offsets(
                    latest_requests,
                    request_timeout=(
                        self._timeout_seconds
                    ),
                )
            )
        except Exception as exc:
            raise KafkaDiagnosticError(
                f"Unable to retrieve Kafka log-end "
                f"offsets for '{normalized_topic}'."
            ) from exc

        latest_offsets = {}

        for tp, latest_future in (
            latest_futures.items()
        ):
            result = self._future_result(
                latest_future,
                "list latest offsets",
            )

            latest_offsets[
                (tp.topic, tp.partition)
            ] = int(result.offset)

        partitions = []
        total_lag = 0
        unknown_offsets = 0

        for tp in sorted(
            committed_partitions,
            key=lambda item: item.partition,
        ):
            current_offset = int(tp.offset)

            log_end_offset = latest_offsets.get(
                (tp.topic, tp.partition)
            )

            if (
                current_offset < 0
                or log_end_offset is None
                or log_end_offset < 0
            ):
                lag = None
                unknown_offsets += 1
            else:
                lag = max(
                    log_end_offset
                    - current_offset,
                    0,
                )
                total_lag += lag

            partitions.append(
                {
                    "partition": tp.partition,
                    "current_offset": (
                        current_offset
                    ),
                    "log_end_offset": (
                        log_end_offset
                    ),
                    "lag": lag,
                }
            )

        summary = (
            f"Kafka consumer group {normalized_group} "
            f"has total lag {total_lag} across "
            f"{len(partitions)} {normalized_topic} "
            f"partition(s)."
        )

        return Evidence(
            incident_id=incident_id,
            source=EvidenceSource.KAFKA,
            tool="get_consumer_lag",
            summary=summary,
            trust_level=(
                EvidenceTrustLevel.DIRECT_OBSERVATION
            ),
            service="processor",
            raw_reference=(
                f"consumer-group={normalized_group} "
                f"topic={normalized_topic}"
            ),
            metadata={
                "group_id": normalized_group,
                "topic": normalized_topic,
                "partition_count": len(
                    partitions
                ),
                "total_lag": total_lag,
                "unknown_offsets": (
                    unknown_offsets
                ),
                "partitions": partitions,
            },
        )
