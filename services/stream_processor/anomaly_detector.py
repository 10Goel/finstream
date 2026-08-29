from services.transaction_generator.customer_profile import CUSTOMERS


CUSTOMER_BY_ID = {
    customer.customer_id: customer
    for customer in CUSTOMERS
}


def analyze_transaction(transaction):
    """
    Analyze a transaction against the customer's normal profile.

    Returns:
        {
            "is_anomalous": bool,
            "risk_score": int,
            "reasons": list[str],
        }
    """

    risk_score = 0
    reasons = []

    customer_id = transaction.get("customer_id")
    customer = CUSTOMER_BY_ID.get(customer_id)

    if customer is None:
        risk_score += 50
        reasons.append("unknown_customer")

        return {
            "is_anomalous": risk_score >= 50,
            "risk_score": min(risk_score, 100),
            "reasons": reasons,
        }

    amount = transaction.get("amount", 0)

    # Amount anomaly
    if amount > customer.max_amount * 5:
        risk_score += 40
        reasons.append("very_high_amount")
    elif amount > customer.max_amount * 2:
        risk_score += 25
        reasons.append("high_amount")

    # Geographic anomaly
    if transaction.get("location") != customer.usual_location:
        risk_score += 25
        reasons.append("unusual_location")

    # Device anomaly
    if transaction.get("device_id") != customer.usual_device:
        risk_score += 20
        reasons.append("new_device")

    # Payment-method anomaly
    if (
        transaction.get("payment_method")
        != customer.usual_payment_method
    ):
        risk_score += 15
        reasons.append("unusual_payment_method")

    risk_score = min(risk_score, 100)

    return {
        "is_anomalous": risk_score >= 50,
        "risk_score": risk_score,
        "reasons": reasons,
    }


def is_anomalous(transaction):
    return analyze_transaction(transaction)["is_anomalous"]
