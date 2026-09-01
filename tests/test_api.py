from unittest.mock import patch

from fastapi.testclient import TestClient

from services.api.main import app


client = TestClient(app)


def sample_transaction(
    transaction_id="TX-TEST-001",
    customer_id="C-10001",
    status="NORMAL",
):
    return {
        "transaction_id": transaction_id,
        "customer_id": customer_id,
        "transaction_time": "2026-08-30T15:00:00+00:00",
        "amount": 5000.00,
        "currency": "INR",
        "location": "Delhi",
        "payment_method": "upi",
        "device_id": "DEV-11111",
        "status": status,
        "risk_score": 0 if status == "NORMAL" else 85,
        "alert_reason": None if status == "NORMAL" else "very_high_amount",
        "processed_at": "2026-08-30T15:00:01+00:00",
    }


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@patch("services.api.main.get_transactions")
def test_get_transactions(mock_get_transactions):
    mock_get_transactions.return_value = [
        sample_transaction(),
        sample_transaction("TX-TEST-002"),
    ]

    response = client.get("/transactions?limit=2")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert len(response.json()["transactions"]) == 2


@patch("services.api.main.get_transaction_by_id")
def test_get_transaction_by_id(mock_get_transaction):
    mock_get_transaction.return_value = sample_transaction()

    response = client.get("/transactions/TX-TEST-001")

    assert response.status_code == 200
    assert response.json()["transaction_id"] == "TX-TEST-001"


@patch("services.api.main.get_transaction_by_id")
def test_transaction_not_found(mock_get_transaction):
    mock_get_transaction.return_value = None

    response = client.get("/transactions/TX-NOT-FOUND")

    assert response.status_code == 404
    assert response.json()["detail"] == "Transaction not found"


@patch("services.api.main.get_alerts")
def test_get_alerts(mock_get_alerts):
    mock_get_alerts.return_value = [
        sample_transaction(
            transaction_id="TX-ALERT-001",
            status="ALERT",
        )
    ]

    response = client.get("/alerts?limit=5")

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["alerts"][0]["status"] == "ALERT"


@patch("services.api.main.get_customer_transactions")
def test_customer_transactions(mock_get_customer_transactions):
    mock_get_customer_transactions.return_value = [
        sample_transaction(customer_id="C-10003")
    ]

    response = client.get(
        "/customers/C-10003/transactions?limit=5"
    )

    assert response.status_code == 200
    assert response.json()["customer_id"] == "C-10003"
    assert response.json()["count"] == 1


@patch("services.api.main.get_customer_transactions")
def test_customer_not_found(mock_get_customer_transactions):
    mock_get_customer_transactions.return_value = []

    response = client.get(
        "/customers/C-99999/transactions"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Customer not found"


@patch("services.api.main.get_transaction_stats")
def test_stats(mock_get_stats):
    mock_get_stats.return_value = {
        "total_transactions": 78,
        "normal_transactions": 76,
        "alert_transactions": 2,
        "total_amount": 748204.85,
        "average_amount": 9592.37,
        "average_risk_score": 2.18,
    }

    response = client.get("/stats")

    assert response.status_code == 200

    data = response.json()

    assert data["total_transactions"] == 78
    assert data["normal_transactions"] == 76
    assert data["alert_transactions"] == 2


def test_invalid_status_filter():
    response = client.get(
        "/transactions?status=INVALID"
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "status must be NORMAL or ALERT"
    )


@patch("services.api.main.get_transactions")
def test_combined_filters(mock_get_transactions):
    mock_get_transactions.return_value = [
        sample_transaction(customer_id="C-10003")
    ]

    response = client.get(
        "/transactions"
        "?status=NORMAL"
        "&customer_id=C-10003"
        "&min_amount=1000"
        "&limit=10"
    )

    assert response.status_code == 200

    mock_get_transactions.assert_called_once_with(
        limit=10,
        status="NORMAL",
        customer_id="C-10003",
        min_amount=1000.0,
    )
