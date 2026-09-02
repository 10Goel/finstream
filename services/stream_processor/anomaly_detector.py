from services.transaction_generator.customer_profile import CUSTOMERS

CUSTOMER_BY_ID = {
    customer.customer_id: customer
    for customer in CUSTOMERS
}


def analyze_transaction(transaction):
    customer_id = transaction.get("customer_id")
    customer = CUSTOMER_BY_ID.get(customer_id)

    if customer is None:
        return {
            "is_anomalous": True,
            "risk_score": 50,
            "reason": "unknown_customer",
        }

    amount = transaction.get("amount", 0)

    # Rule 1: Amount anomaly
    if amount > customer.max_amount * 5:
        return {
            "is_anomalous": True,
            "risk_score": 85,
            "reason": "very_high_amount",
        }

    # Rule 2: Geographic anomaly
    if transaction.get("location") != customer.usual_location:
        return {
            "is_anomalous": True,
            "risk_score": 70,
            "reason": "unusual_location",
        }

    # Rule 3: Device anomaly
    if transaction.get("device_id") != customer.usual_device:
        return {
            "is_anomalous": True,
            "risk_score": 60,
            "reason": "new_device",
        }

    # Rule 4: Payment-method anomaly
    if (
        transaction.get("payment_method")
        != customer.usual_payment_method
    ):
        return {
            "is_anomalous": True,
            "risk_score": 55,
            "reason": "unusual_payment_method",
        }

    return {
        "is_anomalous": False,
        "risk_score": 0,
        "reason": "none",
    }


def is_anomalous(transaction):
    return analyze_transaction(transaction)["is_anomalous"]
