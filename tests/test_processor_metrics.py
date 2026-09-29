from prometheus_client import REGISTRY

from services.stream_processor import kafka_consumer
from services.stream_processor.dlq import send_to_dlq
from services.stream_processor.metrics import record_invalid_transaction


def metric_value(name, labels=None):
    value = REGISTRY.get_sample_value(
        name,
        labels=labels,
    )

    return 0 if value is None else value


def sample_transaction():
    return {
        "transaction_id": "TX-test",
        "customer_id": "C-10001",
        "amount": 1000.0,
    }


def test_normal_processed_transaction_metric_increments(monkeypatch):
    labels = {"status": "NORMAL"}

    before = metric_value(
        "finstream_processor_transactions_processed_total",
        labels,
    )

    monkeypatch.setattr(
        kafka_consumer,
        "analyze_transaction",
        lambda transaction: {
            "is_anomalous": False,
            "risk_score": 0,
            "reason": "none",
        },
    )

    monkeypatch.setattr(
        kafka_consumer,
        "save_transaction",
        lambda transaction, analysis: None,
    )

    kafka_consumer.process_transaction(
        sample_transaction()
    )

    after = metric_value(
        "finstream_processor_transactions_processed_total",
        labels,
    )

    assert after == before + 1


def test_alert_transaction_metrics_increment(monkeypatch):
    processed_labels = {"status": "ALERT"}
    alert_labels = {"reason": "new_device"}

    processed_before = metric_value(
        "finstream_processor_transactions_processed_total",
        processed_labels,
    )

    alerts_before = metric_value(
        "finstream_processor_alerts_total",
        alert_labels,
    )

    monkeypatch.setattr(
        kafka_consumer,
        "analyze_transaction",
        lambda transaction: {
            "is_anomalous": True,
            "risk_score": 60,
            "reason": "new_device",
        },
    )

    monkeypatch.setattr(
        kafka_consumer,
        "save_transaction",
        lambda transaction, analysis: None,
    )

    kafka_consumer.process_transaction(
        sample_transaction()
    )

    processed_after = metric_value(
        "finstream_processor_transactions_processed_total",
        processed_labels,
    )

    alerts_after = metric_value(
        "finstream_processor_alerts_total",
        alert_labels,
    )

    assert processed_after == processed_before + 1
    assert alerts_after == alerts_before + 1


def test_invalid_transaction_metric_increments():
    labels = {"reason": "malformed_json"}

    before = metric_value(
        "finstream_processor_invalid_transactions_total",
        labels,
    )

    record_invalid_transaction("malformed_json")

    after = metric_value(
        "finstream_processor_invalid_transactions_total",
        labels,
    )

    assert after == before + 1


class FakeDLQProducer:
    def produce(self, topic, value):
        self.topic = topic
        self.value = value

    def poll(self, timeout):
        self.timeout = timeout


def test_dlq_metric_increments():
    before = metric_value(
        "finstream_processor_dlq_messages_total"
    )

    producer = FakeDLQProducer()

    send_to_dlq(
        producer,
        '{"bad": "message"}',
        "malformed_json",
    )

    after = metric_value(
        "finstream_processor_dlq_messages_total"
    )

    assert after == before + 1
