import json
import time
import logging
import re
import sys
import os
from pathlib import Path
from prometheus_client import start_http_server, Counter, Gauge, Histogram

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.kafka_scripts import KafkaConsumerService
from helper_functions.features_extractor import perform_lexical_analysis, perform_deep_analysis, has_risk_keywords

URLS_PROCESSED = Counter('worker_urls_processed_total', 'URLs processed', ['risk_level'])
IN_PROGRESS = Gauge('worker_urls_in_progress', 'URLs currently being processed')
PREDICTION_LABEL = Counter('worker_prediction_label_total', 'Prediction labels', ['label'])
PREDICTION_CONFIDENCE = Histogram('worker_prediction_confidence', 'Prediction confidence scores', buckets=(0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0))
MALICIOUS_PROBABILITY = Histogram('worker_malicious_probability', 'Malicious probability scores', buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0))

# Import ML prediction modules
try:
    from ml_scripts.predictor import URLPredictor
    ML_MODELS_AVAILABLE = True
except ImportError as e:
    ML_MODELS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to import ML models: {e}")
    logger.error("Run training first and ensure ml_scripts/ folder exists")
    URLPredictor = None  # Define as None so later code can check

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Kafka Configuration
KAFKA_TOPIC = "url_submission"
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
GROUP_ID = "url_scanner_group"

# Model paths (update after training)
LIGHTWEIGHT_MODEL_PATH = "models/xgboost_model.pkl"
DEEP_MODEL_PATH = "models/xgboost_model.pkl"
WHITELIST_PATH = "datasets/raw/cleaned_topreal_urls.csv"

# Initialize predictor (assume models exist)
if not ML_MODELS_AVAILABLE or URLPredictor is None:
    logger.error("URLPredictor not available - check imports")
    sys.exit(1)

try:
    predictor = URLPredictor(
        lightweight_model_path=LIGHTWEIGHT_MODEL_PATH,
        deep_model_path=DEEP_MODEL_PATH,
        whitelist_path=WHITELIST_PATH
    )
    logger.info("ML models loaded successfully")
    logger.info(f"Lightweight model: {LIGHTWEIGHT_MODEL_PATH}")
    logger.info(f"Deep model: {DEEP_MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load models: {e}")
    logger.error("Ensure models are trained and saved at:")
    logger.error(f"  {LIGHTWEIGHT_MODEL_PATH}")
    logger.error(f"  {DEEP_MODEL_PATH}")
    sys.exit(1)


def process_url(data):
    url = data.get("url")
    if not url:
        return
    IN_PROGRESS.inc()

    logger.info(f"Received URL: {url}")

    high_risk = has_risk_keywords(url) > 0
    
    if high_risk:
        logger.warning(f"[HIGH RISK] URL contains suspicious keywords")
    
    # Both paths: perform lexical analysis and ML prediction
    try:
        # Extract lexical features
        features_df = perform_lexical_analysis(url)
        
        # Run through ML model (lightweight only for now)
        result = predictor.predict_single_url(url, return_confidence=True)
        
        # Log results
        logger.info(f"[PREDICTION] URL: {url}")
        logger.info(f"[PREDICTION] Label: {result['label'].upper()}")
        logger.info(f"[PREDICTION] Confidence: {result['confidence']:.2%}")
        logger.info(f"[PREDICTION] Malicious Probability: {result['malicious_probability']:.2%}")
        
        # Export metrics for Grafana
        PREDICTION_LABEL.labels(label=result['label']).inc()
        PREDICTION_CONFIDENCE.observe(result['confidence'])
        MALICIOUS_PROBABILITY.observe(result['malicious_probability'])
        
        # Alert if malicious
        if result['label'] == 'malicious':
            logger.warning(f"[ALERT] Malicious URL detected: {url}")
        
    except Exception as e:
        logger.error(f"Error processing URL {url}: {e}")
    finally:
        IN_PROGRESS.dec()
        risk_level = "high" if high_risk else "low"
        URLS_PROCESSED.labels(risk_level=risk_level).inc()

def start_consumer():
    consumer_service = KafkaConsumerService(KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, GROUP_ID)
    start_http_server(8001)
    logger.info(f"Listening for messages on topic '{KAFKA_TOPIC}'...")
    consumer_service.start_listening(process_url)


if __name__ == "__main__":
    start_consumer()
