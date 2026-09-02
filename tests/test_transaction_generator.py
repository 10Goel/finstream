from datetime import datetime

from services.transaction_generator.generator import generate_transaction


def test_transaction_contains_required_fields():
    transaction = generate_transaction()

    required_fields = {
        "transaction_id",
        "customer_id",
        "timestamp",
        "amount",
        "currency",
        "location",
        "payment_method",
        "device_id",
        "suspicious",
        "anomaly_type",
    }

    assert required_fields.issubset(transaction.keys())


def test_normal_transaction():
    transaction = generate_transaction()

    assert transaction["transaction_id"].startswith("TX-")
    assert transaction["customer_id"].startswith("C-")
    assert transaction["amount"] >= 0
    assert transaction["currency"] == "INR"
    assert transaction["suspicious"] is False
    assert transaction["anomaly_type"] is None


def test_transaction_timestamp_is_valid_iso_format():
    transaction = generate_transaction()

    timestamp = datetime.fromisoformat(transaction["timestamp"])

    assert timestamp.tzinfo is not None


def test_high_amount_anomaly_generates_high_amount():
    transaction = generate_transaction(
        suspicious=True,
        anomaly_type="high_amount",
    )

    assert transaction["suspicious"] is True
    assert transaction["anomaly_type"] == "high_amount"
    assert transaction["amount"] >= 2500


def test_suspicious_transaction_has_anomaly_type():
    transaction = generate_transaction(
        suspicious=True,
    )

    assert transaction["suspicious"] is True

    assert transaction["anomaly_type"] in {
        "high_amount",
        "unusual_location",
        "new_device",
        "unusual_payment_method",
    }
