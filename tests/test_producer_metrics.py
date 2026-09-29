from prometheus_client import REGISTRY

from services.transaction_generator.kafka_producer import delivery_report
from services.transaction_generator.metrics import (
    record_generated_transaction,
)


class FakeKafkaMessage:
    def key(self):
        return b"C-10001"

    def topic(self):
        return "transactions"

    def partition(self):
        return 0

    def offset(self):
        return 1


def metric_value(name, labels=None):
    value = REGISTRY.get_sample_value(
        name,
        labels=labels,
    )

    return 0 if value is None else value


def test_generated_normal_transaction_metric_increments():
    labels = {"suspicious": "false"}

    before = metric_value(
        "finstream_producer_transactions_generated_total",
        labels,
    )

    record_generated_transaction(
        {
            "suspicious": False,
        }
    )

    after = metric_value(
        "finstream_producer_transactions_generated_total",
        labels,
    )

    assert after == before + 1


def test_generated_suspicious_transaction_metric_increments():
    labels = {"suspicious": "true"}

    before = metric_value(
        "finstream_producer_transactions_generated_total",
        labels,
    )

    record_generated_transaction(
        {
            "suspicious": True,
        }
    )

    after = metric_value(
        "finstream_producer_transactions_generated_total",
        labels,
    )

    assert after == before + 1


def test_successful_delivery_metric_increments():
    before = metric_value(
        "finstream_producer_transactions_published_total"
    )

    delivery_report(
        None,
        FakeKafkaMessage(),
    )

    after = metric_value(
        "finstream_producer_transactions_published_total"
    )

    assert after == before + 1


def test_failed_delivery_metric_increments():
    before = metric_value(
        "finstream_producer_delivery_failures_total"
    )

    delivery_report(
        "simulated Kafka failure",
        FakeKafkaMessage(),
    )

    after = metric_value(
        "finstream_producer_delivery_failures_total"
    )

    assert after == before + 1
