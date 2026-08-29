import json

from confluent_kafka import Producer

from services.transaction_generator.generator import generate_transaction


KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "transactions"


def delivery_report(err, msg):
    if err is not None:
        print(f"Message delivery failed: {err}")
    else:
        print(
            f"Transaction delivered to "
            f"{msg.topic()} [partition {msg.partition()}] "
            f"at offset {msg.offset()}"
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


if __name__ == "__main__":
    producer = create_producer()

    transaction = generate_transaction()

    print("Generated transaction:")
    print(json.dumps(transaction, indent=2))

    publish_transaction(producer, transaction)

    producer.flush()
