import json
import random
import uuid
from datetime import datetime, timezone


def generate_transaction():
    transaction = {
        "transaction_id": f"TX-{uuid.uuid4().hex[:8]}",
        "customer_id": f"C-{random.randint(10000, 99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "amount": round(random.uniform(100, 100000), 2),
        "currency": "INR",
        "merchant_id": f"M-{random.randint(1000, 9999)}",
        "merchant_category": random.choice(
            [
                "grocery",
                "electronics",
                "restaurants",
                "travel",
                "utilities",
                "fashion",
            ]
        ),
        "location": random.choice(
            [
                "Delhi",
                "Mumbai",
                "Bangalore",
                "Chennai",
                "Hyderabad",
                "Pune",
            ]
        ),
        "payment_method": random.choice(
            [
                "card",
                "upi",
                "net_banking",
            ]
        ),
        "device_id": f"DEV-{random.randint(10000, 99999)}",
    }

    return transaction


if __name__ == "__main__":
    transaction = generate_transaction()
    print(json.dumps(transaction, indent=2))
