from services.transaction_generator.generator import generate_transaction


def test_transaction_contains_required_fields():
    transaction = generate_transaction()

    required_fields = {
        "transaction_id",
        "customer_id",
        "timestamp",
        "amount",
        "currency",
        "merchant_id",
        "merchant_category",
        "location",
        "payment_method",
        "device_id",
    }

    assert required_fields.issubset(transaction.keys())


def test_transaction_amount_is_positive():
    transaction = generate_transaction()

    assert transaction["amount"] > 0


def test_transaction_currency_is_inr():
    transaction = generate_transaction()

    assert transaction["currency"] == "INR"
