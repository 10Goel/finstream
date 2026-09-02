from services.stream_processor.anomaly_detector import (
    analyze_transaction,
)


def test_normal_transaction():
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
    assert result["reason"] == "none"


def test_very_high_amount():
    transaction = {
        "customer_id": "C-10001",
        "amount": 80000,
        "location": "Delhi",
        "device_id": "DEV-11111",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 85
    assert result["reason"] == "very_high_amount"


def test_unusual_location():
    transaction = {
        "customer_id": "C-10001",
        "amount": 2500,
        "location": "Dubai",
        "device_id": "DEV-11111",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 70
    assert result["reason"] == "unusual_location"


def test_new_device():
    transaction = {
        "customer_id": "C-10001",
        "amount": 2500,
        "location": "Delhi",
        "device_id": "DEV-99999",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 60
    assert result["reason"] == "new_device"


def test_unusual_payment_method():
    transaction = {
        "customer_id": "C-10001",
        "amount": 2500,
        "location": "Delhi",
        "device_id": "DEV-11111",
        "payment_method": "card",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 55
    assert result["reason"] == "unusual_payment_method"


def test_unknown_customer():
    transaction = {
        "customer_id": "C-99999",
        "amount": 2500,
        "location": "Delhi",
        "device_id": "DEV-11111",
        "payment_method": "upi",
    }

    result = analyze_transaction(transaction)

    assert result["is_anomalous"] is True
    assert result["risk_score"] == 50
    assert result["reason"] == "unknown_customer"
