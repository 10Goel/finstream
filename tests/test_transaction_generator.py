from services.transaction_generator.generator import generate_transaction


def test_normal_transaction_contains_required_fields():
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
    }

    assert required_fields.issubset(transaction.keys())


def test_normal_transaction_is_not_suspicious():
    transaction = generate_transaction()

    assert transaction["suspicious"] is False


def test_normal_transaction_amount_is_positive():
    transaction = generate_transaction()

    assert transaction["amount"] > 0


def test_suspicious_transaction_is_flagged():
    transaction = generate_transaction(suspicious=True)

    assert transaction["suspicious"] is True


def test_suspicious_transaction_has_high_amount():
    transaction = generate_transaction(suspicious=True)

    assert transaction["amount"] >= 2500
