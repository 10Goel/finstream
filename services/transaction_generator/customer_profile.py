from dataclasses import dataclass


@dataclass
class CustomerProfile:
    customer_id: str
    usual_location: str
    usual_device: str
    min_amount: float
    max_amount: float
    usual_payment_method: str


CUSTOMERS = [
    CustomerProfile(
        customer_id="C-10001",
        usual_location="Delhi",
        usual_device="DEV-11111",
        min_amount=500,
        max_amount=5000,
        usual_payment_method="upi",
    ),
    CustomerProfile(
        customer_id="C-10002",
        usual_location="Mumbai",
        usual_device="DEV-22222",
        min_amount=1000,
        max_amount=10000,
        usual_payment_method="card",
    ),
    CustomerProfile(
        customer_id="C-10003",
        usual_location="Bangalore",
        usual_device="DEV-33333",
        min_amount=2000,
        max_amount=20000,
        usual_payment_method="net_banking",
    ),
]


def get_random_customer():
    import random

    return random.choice(CUSTOMERS)
