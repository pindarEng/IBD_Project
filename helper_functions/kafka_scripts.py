from kafka import KafkaProducer, KafkaConsumer
import json
import logging

logger = logging.getLogger(__name__)

class KafkaProducerService:
    def __init__(self, bootstrap_servers):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
        self._initialize_producer()

    def _initialize_producer(self):
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            logger.info("Kafka Producer initialized successfully.")
        except Exception as e:
            logger.error(f"failed to initialize Kafka Producer: {e}")
            self.producer = None

    def send_url(self, topic, url):
        if not self.producer:
            # Try to reconnect if it failed previously
            self._initialize_producer()
            if not self.producer:
                raise Exception("Kafka Producer is not available")

        future = self.producer.send(topic, {"url": url})
        result = future.get(timeout=10) # Wait for confirmation
        return result
    

class KafkaConsumerService:
    def __init__(self, bootstrap_servers, topic, group_id):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        # self.value_deserializer = lambda x: json.load(x.decode('utf-8'))

    def start_listening(self, message_handler):
        try:
            consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers = self.bootstrap_servers,
                group_id = self.group_id,
                enable_auto_commit = True,
                auto_offset_reset='earliest',
                value_deserializer = lambda x: json.loads(x.decode('utf-8'))
            )
            logger.info(f"listening for messages on topic `{self.topic}' ...")

            for message in consumer:
                message_handler(message.value)

        except Exception as e:
            logger.error(f"error in consumer: {e}")

