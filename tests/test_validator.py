from services.stream_processor.validator import validate_transaction


def valid_transaction():
    return {
        "transaction_id": "TX-TEST-001",
        "customer_id": "C-10001",
        "timestamp": "2026-08-30T10:00:00+00:00",
        "amount": 2500.0,
        "currency": "INR",
        "location": "Delhi",
        "payment_method": "upi",
        "device_id": "DEV-11111",
    }


def test_valid_transaction():
    transaction = valid_transaction()

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is True
    assert reason is None


def test_missing_fields():
    transaction = {
        "transaction_id": "TX-BAD-001",
    }

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason.startswith("missing_fields:")


def test_negative_amount():
    transaction = valid_transaction()
    transaction["amount"] = -500

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "negative_amount"


def test_invalid_amount_type():
    transaction = valid_transaction()
    transaction["amount"] = "2500"

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_amount_type"


def test_invalid_timestamp():
    transaction = valid_transaction()
    transaction["timestamp"] = "not-a-timestamp"

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_timestamp"


def test_unsupported_currency():
    transaction = valid_transaction()
    transaction["currency"] = "XYZ"

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "unsupported_currency"


def test_invalid_payment_method():
    transaction = valid_transaction()
    transaction["payment_method"] = "cash"

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_payment_method"


def test_empty_location():
    transaction = valid_transaction()
    transaction["location"] = ""

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_location"


def test_empty_device_id():
    transaction = valid_transaction()
    transaction["device_id"] = ""

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_device_id"


def test_empty_customer_id():
    transaction = valid_transaction()
    transaction["customer_id"] = ""

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_customer_id"


def test_boolean_amount_is_rejected():
    transaction = valid_transaction()
    transaction["amount"] = True

    is_valid, reason = validate_transaction(transaction)

    assert is_valid is False
    assert reason == "invalid_amount_type"
