import json
import time
import logging
import re
import sys
import os
from pathlib import Path
from prometheus_client import start_http_server, Counter, Gauge

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.kafka_scripts import KafkaConsumerService
from helper_functions.features_extractor import (
    perform_lexical_analysis, 
    perform_deep_analysis, 
    has_risk_keywords
)
from helper_functions.url_expander import (
    expand_url_comprehensive,
    expand_url_aggressive,
    expand_url_if_shortened,
    has_shortening_service
)

URLS_PROCESSED = Counter('worker_urls_processed_total', 'URLs processed', ['risk_level'])
IN_PROGRESS = Gauge('worker_urls_in_progress', 'URLs currently being processed')

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

# URL Expansion Configuration (always enabled with comprehensive mode)
URL_EXPANSION_TIMEOUT = int(os.getenv("URL_EXPANSION_TIMEOUT", "10"))
URL_EXPANSION_MODE = os.getenv("URL_EXPANSION_MODE", "comprehensive").lower()  # comprehensive, aggressive, standard

# Model paths (update after training)
LIGHTWEIGHT_MODEL_PATH = "models/random_forest_model.pkl"
DEEP_MODEL_PATH = "models/xgboost_model.pkl"

# Initialize predictor (assume models exist)
if not ML_MODELS_AVAILABLE or URLPredictor is None:
    logger.error("URLPredictor not available - check imports")
    sys.exit(1)

try:
    predictor = URLPredictor(
        lightweight_model_path=LIGHTWEIGHT_MODEL_PATH,
        deep_model_path=DEEP_MODEL_PATH
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
    
    # Always expand URL before feature extraction (comprehensive mode by default)
    original_url = url
    try:
        if URL_EXPANSION_MODE == "comprehensive":
            # RECOMMENDED: Smart method selection (HTTP first, browser fallback)
            logger.info(f"[URL EXPANSION] Using comprehensive mode for: {url}")
            expansion_result = expand_url_comprehensive(url, timeout=URL_EXPANSION_TIMEOUT)
            
            if expansion_result['was_expanded']:
                url = expansion_result['expanded_url']
                logger.info(f"[URL EXPANSION] ✓ Expanded using {expansion_result['method_used'].upper()}: {url}")
                logger.info(f"[URL EXPANSION] Redirects: {expansion_result['redirect_count']}")
            else:
                logger.debug(f"[URL EXPANSION] No redirects found (not shortened)")
                
        elif URL_EXPANSION_MODE == "aggressive":
            # Try to expand ALL URLs, not just known shorteners
            logger.info(f"[URL EXPANSION] Using aggressive mode for: {url}")
            expansion_result = expand_url_aggressive(url, timeout=URL_EXPANSION_TIMEOUT)
            
            if expansion_result['was_expanded']:
                url = expansion_result['expanded_url']
                logger.info(f"[URL EXPANSION] ✓ Found redirect: {url}")
                logger.info(f"[URL EXPANSION] Redirects: {expansion_result['redirect_count']}")
            else:
                logger.debug(f"[URL EXPANSION] No redirects found")
                
        else:  # standard mode
            # Only expand known shorteners
            if has_shortening_service(url):
                logger.info(f"[URL EXPANSION] Shortened URL detected: {url}")
                expansion_result = expand_url_if_shortened(url, timeout=URL_EXPANSION_TIMEOUT)
                
                if expansion_result['expansion_success'] and expansion_result['expanded_url'] != url:
                    url = expansion_result['expanded_url']
                    logger.info(f"[URL EXPANSION] ✓ Expanded to: {url}")
                    logger.info(f"[URL EXPANSION] Redirects: {expansion_result['redirect_count']}")
                else:
                    logger.warning(f"[URL EXPANSION] Failed to expand, using original")
            else:
                logger.debug(f"[URL EXPANSION] Not a known shortener, skipping")
    except Exception as e:
        logger.error(f"[URL EXPANSION] Error during expansion: {e}")
        logger.warning(f"[URL EXPANSION] Using original URL: {original_url}")
        url = original_url

    high_risk = has_risk_keywords(url) > 0
    
    if high_risk:
        logger.warning(f"[HIGH RISK] URL contains suspicious keywords")
    
    # Both paths: perform lexical analysis and ML prediction
    try:
        # Extract lexical features (use expanded URL)
        features_df = perform_lexical_analysis(url, expand_urls=False)  # Already expanded above
        
        # Run through ML model (lightweight only for now)
        result = predictor.predict_single_url(url, return_confidence=True)
        
        # Log results
        logger.info(f"[PREDICTION] URL: {url}")
        logger.info(f"[PREDICTION] Label: {result['label'].upper()}")
        logger.info(f"[PREDICTION] Confidence: {result['confidence']:.2%}")
        logger.info(f"[PREDICTION] Malicious Probability: {result['malicious_probability']:.2%}")
        
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
    logger.info(f"URL Expansion: ENABLED (always on)")
    mode_description = {
        'comprehensive': 'COMPREHENSIVE (HTTP → Browser fallback, RECOMMENDED)',
        'aggressive': 'AGGRESSIVE (all URLs)',
        'standard': 'STANDARD (known shorteners only)'
    }.get(URL_EXPANSION_MODE, URL_EXPANSION_MODE.upper())
    logger.info(f"URL Expansion Mode: {mode_description}")
    logger.info(f"URL Expansion Timeout: {URL_EXPANSION_TIMEOUT}s")
    consumer_service.start_listening(process_url)


if __name__ == "__main__":
    start_consumer()
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
