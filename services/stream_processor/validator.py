from datetime import datetime

REQUIRED_FIELDS = {
    "transaction_id",
    "customer_id",
    "timestamp",
    "amount",
    "currency",
    "location",
    "payment_method",
    "device_id",
}


ALLOWED_CURRENCIES = {
    "INR",
}


ALLOWED_PAYMENT_METHODS = {
    "card",
    "upi",
    "net_banking",
}


def is_valid_timestamp(value):
    if not isinstance(value, str):
        return False

    try:
        datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
        return True

    except ValueError:
        return False


def validate_transaction(transaction):
    if not isinstance(transaction, dict):
        return False, "transaction_not_object"

    missing_fields = sorted(
        field
        for field in REQUIRED_FIELDS
        if field not in transaction
    )

    if missing_fields:
        return (
            False,
            f"missing_fields:{','.join(missing_fields)}",
        )

    transaction_id = transaction["transaction_id"]

    if (
        not isinstance(transaction_id, str)
        or not transaction_id.strip()
    ):
        return False, "invalid_transaction_id"

    customer_id = transaction["customer_id"]

    if (
        not isinstance(customer_id, str)
        or not customer_id.strip()
    ):
        return False, "invalid_customer_id"

    amount = transaction["amount"]

    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
    ):
        return False, "invalid_amount_type"

    if amount < 0:
        return False, "negative_amount"

    if not is_valid_timestamp(transaction["timestamp"]):
        return False, "invalid_timestamp"

    currency = transaction["currency"]

    if currency not in ALLOWED_CURRENCIES:
        return False, "unsupported_currency"

    payment_method = transaction["payment_method"]

    if payment_method not in ALLOWED_PAYMENT_METHODS:
        return False, "invalid_payment_method"

    location = transaction["location"]

    if (
        not isinstance(location, str)
        or not location.strip()
    ):
        return False, "invalid_location"

    device_id = transaction["device_id"]

    if (
        not isinstance(device_id, str)
        or not device_id.strip()
    ):
        return False, "invalid_device_id"

    return True, None
