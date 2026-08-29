import json
import time

from confluent_kafka import Producer

from services.transaction_generator.generator import generate_transaction


KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "transactions"


def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")
    else:
        print(
            f"Delivered {msg.key().decode() if msg.key() else 'transaction'} "
            f"to {msg.topic()} "
            f"[partition {msg.partition()}] "
            f"offset {msg.offset()}"
        )


def create_producer():
    return Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        }
    )


def publish_transaction(producer, transaction):
    message = json.dumps(transaction).encode("utf-8")

    producer.produce(
        topic=KAFKA_TOPIC,
        value=message,
        callback=delivery_report,
    )

    producer.poll(0)


def main():
    producer = create_producer()

    print("Starting FinStream transaction producer...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            transaction = generate_transaction()

            print(
                f"Generated transaction: "
                f"{transaction['transaction_id']} | "
                f"Amount: ₹{transaction['amount']} | "
                f"Suspicious: {transaction['suspicious']}"
            )

            publish_transaction(producer, transaction)

            time.sleep(2)

    except KeyboardInterrupt:
        print("\nStopping transaction producer...")

    finally:
        producer.flush()
        print("Producer stopped.")


if __name__ == "__main__":
    main()
