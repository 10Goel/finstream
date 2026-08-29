from services.stream_processor.anomaly_detector import (
    analyze_transaction,
)


def test_normal_transaction_has_low_risk():
    transaction = {
        "customer_id": "C-10001",
        "amount": 2500,
        "location": "Delhi",
        "device_id": "DEV-11111",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is False
    assert result["risk_score"] == 0
    assert result["reasons"] == []


def test_large_foreign_transaction_is_anomalous():
    transaction = {
        "customer_id": "C-10001",
        "amount": 80000,
        "location": "Dubai",
        "device_id": "DEV-99999",
        "payment_method": "card",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] >= 50
    assert "very_high_amount" in result["reasons"]
    assert "unusual_location" in result["reasons"]
    assert "new_device" in result["reasons"]


def test_new_device_alone_does_not_trigger_alert():
    transaction = {
        "customer_id": "C-10001",
        "amount": 2000,
        "location": "Delhi",
        "device_id": "DEV-99999",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is False
    assert result["risk_score"] == 20
    assert "new_device" in result["reasons"]


def test_unknown_customer_is_anomalous():
    transaction = {
        "customer_id": "C-99999",
        "amount": 1000,
        "location": "Delhi",
        "device_id": "DEV-12345",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 50
    assert "unknown_customer" in result["reasons"]
