import json
import random
import uuid
from datetime import datetime, timezone

from services.transaction_generator.customer_profile import (
    get_random_customer,
)


def generate_transaction(suspicious=False):
    customer = get_random_customer()

    if suspicious:
        amount = round(
            random.uniform(
                customer.max_amount * 5,
                customer.max_amount * 20,
            ),
            2,
        )

        location = random.choice(
            [
                "London",
                "New York",
                "Dubai",
                "Singapore",
            ]
        )

        device = f"DEV-{random.randint(90000, 99999)}"

        payment_method = random.choice(
            [
                "card",
                "net_banking",
            ]
        )

    else:
        amount = round(
            random.uniform(
                customer.min_amount,
                customer.max_amount,
            ),
            2,
        )

        location = customer.usual_location
        device = customer.usual_device
        payment_method = customer.usual_payment_method

    return {
        "transaction_id": f"TX-{uuid.uuid4().hex[:8]}",
        "customer_id": customer.customer_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": amount,
        "currency": "INR",
        "location": location,
        "payment_method": payment_method,
        "device_id": device,
        "suspicious": suspicious,
    }


if __name__ == "__main__":
    normal_transaction = generate_transaction()

    suspicious_transaction = generate_transaction(
        suspicious=True
    )

    print("Normal transaction:")
    print(json.dumps(normal_transaction, indent=2))

    print("\nSuspicious transaction:")
    print(json.dumps(suspicious_transaction, indent=2))
