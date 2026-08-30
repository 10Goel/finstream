import json
import os
from services.database.postgres import save_transaction

from confluent_kafka import Consumer, KafkaError

from services.stream_processor.anomaly_detector import (
    analyze_transaction,
)


KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC",
    "transactions",
)

CONSUMER_GROUP = "finstream-anomaly-detector"


def create_consumer():
    return Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": CONSUMER_GROUP,
            "auto.offset.reset": "latest",
        }
    )


def process_transaction(transaction):
    result = analyze_transaction(transaction)

    status = (
        "ALERT"
        if result["is_anomalous"]
        else "NORMAL"
    )

    print(
        f"[{status}] "
        f"{transaction['transaction_id']} | "
        f"Customer: {transaction['customer_id']} | "
        f"Amount: ₹{transaction['amount']} | "
        f"Risk: {result['risk_score']} | "
        f"Reason: {result['reason']}"
    )

    save_transaction(
        transaction=transaction,
        analysis=result,
    )

def main():
    consumer = create_consumer()

    consumer.subscribe([KAFKA_TOPIC])

    print("Starting FinStream anomaly detector...")
    print(f"Consumer group: {CONSUMER_GROUP}")
    print(f"Listening to topic: {KAFKA_TOPIC}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            message = consumer.poll(1.0)

            if message is None:
                continue

            if message.error():
                if (
                    message.error().code()
                    != KafkaError._PARTITION_EOF
                ):
                    print(f"Kafka error: {message.error()}")

                continue

            transaction = json.loads(
                message.value().decode("utf-8")
            )

            process_transaction(transaction)

    except KeyboardInterrupt:
        print("\nStopping anomaly detector...")

    finally:
        consumer.close()
        print("Consumer stopped.")


if __name__ == "__main__":
    main()
