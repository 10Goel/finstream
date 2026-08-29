import json
import os
import time

from confluent_kafka import Producer

from services.transaction_generator.generator import generate_transaction


KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_TOPIC",
    "transactions",
)


def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")
        return

    key = msg.key().decode("utf-8") if msg.key() else "None"

    print(
        f"Delivered transaction for customer {key} "
        f"to {msg.topic()} "
        f"[partition {msg.partition()}] "
        f"offset {msg.offset()}"
    )


def create_producer():
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,

        # Reliability
        "acks": "all",
        "retries": 5,

        # Small batching optimization
        "linger.ms": 5,
    }

    return Producer(config)


def publish_transaction(producer, transaction):
    message = json.dumps(transaction).encode("utf-8")

    # Customer ID is the Kafka message key.
    # Kafka uses the key to determine the partition.
    key = transaction["customer_id"].encode("utf-8")

    producer.produce(
        topic=KAFKA_TOPIC,
        key=key,
        value=message,
        callback=delivery_report,
    )

    producer.poll(0)


def main():
    producer = create_producer()

    print("Starting FinStream transaction producer...")
    print(f"Kafka broker: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"Kafka topic: {KAFKA_TOPIC}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            transaction = generate_transaction()

            print(
                f"Generated transaction: "
                f"{transaction['transaction_id']} | "
                f"Customer: {transaction['customer_id']} | "
                f"Amount: ₹{transaction['amount']} | "
                f"Suspicious: {transaction['suspicious']}"
            )

            publish_transaction(producer, transaction)

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nStopping transaction producer...")

    finally:
        remaining = producer.flush()

        if remaining:
            print(f"Warning: {remaining} message(s) were not delivered.")

        print("Producer stopped.")


if __name__ == "__main__":
    main()
