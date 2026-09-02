import json
import random
import uuid
from datetime import datetime, timezone

from services.transaction_generator.customer_profile import (
    get_random_customer,
)

LOCATIONS = [
    "Delhi",
    "Mumbai",
    "Bangalore",
    "Chennai",
    "Hyderabad",
    "Pune",
    "Dubai",
    "London",
    "Singapore",
]

PAYMENT_METHODS = [
    "card",
    "upi",
    "net_banking",
]


def generate_transaction(suspicious=False):
    customer = get_random_customer()

    # Start with completely normal customer behaviour.
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

    anomaly_type = None

    if suspicious:
        anomaly_type = random.choice(
            [
                "high_amount",
                "unusual_location",
                "new_device",
                "unusual_payment_method",
            ]
        )

        if anomaly_type == "high_amount":
            amount = round(
                random.uniform(
                    customer.max_amount * 6,
                    customer.max_amount * 15,
                ),
                2,
            )

        elif anomaly_type == "unusual_location":
            unusual_locations = [
                location_name
                for location_name in LOCATIONS
                if location_name != customer.usual_location
            ]

            location = random.choice(unusual_locations)

        elif anomaly_type == "new_device":
            device = f"DEV-{random.randint(90000, 99999)}"

        elif anomaly_type == "unusual_payment_method":
            unusual_methods = [
                method
                for method in PAYMENT_METHODS
                if method != customer.usual_payment_method
            ]

            payment_method = random.choice(unusual_methods)

    transaction = {
        "transaction_id": f"TX-{uuid.uuid4().hex[:8]}",
        "customer_id": customer.customer_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": amount,
        "currency": "INR",
        "location": location,
        "payment_method": payment_method,
        "device_id": device,

        # Synthetic ground-truth fields.
        "suspicious": suspicious,
        "anomaly_type": anomaly_type,
    }

    return transaction


if __name__ == "__main__":
    normal_transaction = generate_transaction()

    suspicious_transaction = generate_transaction(
        suspicious=True
    )

    print("Normal transaction:")
    print(json.dumps(normal_transaction, indent=2))

    print("\nSuspicious transaction:")
    print(json.dumps(suspicious_transaction, indent=2))
