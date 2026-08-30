from unittest.mock import MagicMock, patch

from services.database.postgres import save_transaction


def test_save_normal_transaction():
    transaction = {
        "transaction_id": "TX-TEST-001",
        "customer_id": "C-10001",
        "timestamp": "2026-08-30T10:00:00+00:00",
        "amount": 2500.00,
        "currency": "INR",
        "location": "Delhi",
        "payment_method": "upi",
        "device_id": "DEV-11111",
    }

    analysis = {
        "is_anomalous": False,
        "risk_score": 0,
        "reason": "none",
    }

    connection = MagicMock()
    cursor = MagicMock()

    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor

    with patch(
        "services.database.postgres.get_connection",
        return_value=connection,
    ):
        save_transaction(transaction, analysis)

    cursor.execute.assert_called_once()

    values = cursor.execute.call_args[0][1]

    assert values[0] == "TX-TEST-001"
    assert values[8] == "NORMAL"
    assert values[9] == 0
    assert values[10] is None


def test_save_alert_transaction():
    transaction = {
        "transaction_id": "TX-TEST-002",
        "customer_id": "C-10003",
        "timestamp": "2026-08-30T10:00:00+00:00",
        "amount": 100000.00,
        "currency": "INR",
        "location": "Bangalore",
        "payment_method": "net_banking",
        "device_id": "DEV-33333",
    }

    analysis = {
        "is_anomalous": True,
        "risk_score": 85,
        "reason": "very_high_amount",
    }

    connection = MagicMock()
    cursor = MagicMock()

    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor

    with patch(
        "services.database.postgres.get_connection",
        return_value=connection,
    ):
        save_transaction(transaction, analysis)

    cursor.execute.assert_called_once()

    values = cursor.execute.call_args[0][1]

    assert values[0] == "TX-TEST-002"
    assert values[8] == "ALERT"
    assert values[9] == 85
    assert values[10] == "very_high_amount"
