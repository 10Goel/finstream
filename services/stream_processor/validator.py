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


def validate_transaction(transaction):
    if not isinstance(transaction, dict):
        return False, "transaction_not_object"

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if field not in transaction
    ]

    if missing_fields:
        return (
            False,
            f"missing_fields:{','.join(sorted(missing_fields))}",
        )

    if not isinstance(transaction["amount"], (int, float)):
        return False, "invalid_amount_type"

    if transaction["amount"] < 0:
        return False, "negative_amount"

    if not transaction["transaction_id"]:
        return False, "empty_transaction_id"

    if not transaction["customer_id"]:
        return False, "empty_customer_id"

    return True, None
