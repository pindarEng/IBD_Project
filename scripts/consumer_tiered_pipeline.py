import json
import time
import logging
import re
from helper_functions.kafka_scripts import KafkaConsumerService
from helper_functions.features_extractor import perform_lexical_analysis, perform_deep_analysis ,has_risk_keywords


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Kafka Configuration
KAFKA_TOPIC = "url_submission"
KAFKA_BOOTSTRAP_SERVERS = "kafka:29092"
GROUP_ID = "url_scanner_group"

def process_url(data):
    url = data.get("url")
    
    if not url:
        return

    logger.info(f"Received URL: {url}")

    high_risk = has_risk_keywords(url) > 0
    
    if high_risk:
        logger.warning(f"high risk word detected going all in")
        # perform_lexical_analysis(url)
        resulted_df = perform_lexical_analysis(url)
        #TODO:better deep analysis - whois, dns
        perform_deep_analysis(resulted_df)

        #TODO:deep model with more deep features
    else:
        # faster path just lexical 
        perform_lexical_analysis(url)
        #TODO:simple lexical features model


def start_consumer():
    consumer_service = KafkaConsumerService(KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, GROUP_ID)
    logger.info(f"Listening for messages on topic '{KAFKA_TOPIC}'...")
    consumer_service.start_listening(process_url)


if __name__ == "__main__":
    start_consumer()
