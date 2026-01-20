from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import json
import logging
import sys
import os
from typing import Optional
from prometheus_client import make_asgi_app, Counter, Histogram

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.kafka_scripts import KafkaProducerService

# Try to load ML predictor for synchronous predictions
try:
    from ml_scripts.predictor import URLPredictor
    from pathlib import Path
    
    # Get absolute path to models directory
    SCRIPT_DIR = Path(__file__).parent.parent
    LIGHTWEIGHT_MODEL_PATH = str(SCRIPT_DIR / "models" / "xgboost_model.pkl")
    DEEP_MODEL_PATH = str(SCRIPT_DIR / "models" / "xgboost_model.pkl")
    WHITELIST_PATH = str(SCRIPT_DIR / "datasets" / "raw" / "cleaned_topreal_urls.csv")
    
    logger = logging.getLogger(__name__)
    logger.info(f"Looking for models at: {LIGHTWEIGHT_MODEL_PATH}")
    logger.info(f"Looking for models at: {DEEP_MODEL_PATH}")
    logger.info(f"Looking for whitelist at: {WHITELIST_PATH}")
    
    # Check if model files exist
    if not Path(LIGHTWEIGHT_MODEL_PATH).exists():
        raise FileNotFoundError(f"Lightweight model not found at {LIGHTWEIGHT_MODEL_PATH}")
    if not Path(DEEP_MODEL_PATH).exists():
        raise FileNotFoundError(f"Deep model not found at {DEEP_MODEL_PATH}")
    
    predictor = URLPredictor(
        lightweight_model_path=LIGHTWEIGHT_MODEL_PATH,
        deep_model_path=DEEP_MODEL_PATH,
        whitelist_path=WHITELIST_PATH
    )
    ML_AVAILABLE = True
    logging.info("ML models loaded successfully")
except Exception as e:
    logging.error(f"ML models not available: {e}")
    predictor = None
    ML_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="URL Scanner API",
    description="Submit URLs for malicious content detection using ML models",
    version="1.0.0"
)
REQUEST_COUNT = Counter('api_requests_total', 'Total URL submissions', ['status'])
REQUEST_LATENCY = Histogram('api_latency_seconds', 'Time spent processing request')

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)
# Kafka Configuration
KAFKA_TOPIC = "url_submission"
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")

# Initialize Producer (Global)
try:
    producer_service = KafkaProducerService(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
except Exception as e:
    logger.error(f"failed initialization for kafka producer: {e}")
    producer_service = None

class URLSubmission(BaseModel):
    url: str = Field(..., example="http://test.com.xyz/malware", description="URL to scan for malicious content")


class PredictionResult(BaseModel):
    url: str = Field(..., description="The scanned URL")
    label: str = Field(..., description="Prediction label: BENIGN or MALICIOUS", example="MALICIOUS")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score (0.0 to 1.0)", example=0.5113)
    malicious_probability: float = Field(..., ge=0, le=1, description="Probability of malicious (0.0 to 1.0)", example=0.5113)
    benign_probability: Optional[float] = Field(None, ge=0, le=1, description="Probability of benign (0.0 to 1.0)", example=0.4887)
    status: str = Field(..., description="Status of the analysis", example="analyzed")


@app.post("/scan/", response_model=PredictionResult, tags=["URL Scanning"])
async def scan_url(submission: URLSubmission):
    with REQUEST_LATENCY.time():
        if not ML_AVAILABLE or predictor is None:
            raise HTTPException(status_code=503, detail="ML models not loaded")

        try:
            logger.info(f"Received URL: {submission.url}")
            
            # Get immediate prediction
            result = predictor.predict_single_url(submission.url, return_confidence=True)
            
            logger.info(f"[PREDICTION] URL: {submission.url}")
            logger.info(f"[PREDICTION] Label: {result['label'].upper()}")
            logger.info(f"[PREDICTION] Confidence: {result['confidence']:.2%}")
            logger.info(f"[PREDICTION] Malicious Probability: {result['malicious_probability']:.2%}")
            
            if result['label'] == 'malicious':
                logger.warning(f"[ALERT] Malicious URL detected: {submission.url}")
            
            # Also queue to Kafka for logging/monitoring (optional)
            if producer_service and producer_service.producer:
                try:
                    producer_service.send_url(KAFKA_TOPIC, submission.url)
                except Exception as kafka_err:
                    logger.warning(f"Failed to send to Kafka: {kafka_err}")
                
            REQUEST_COUNT.labels(status="success").inc()

            return PredictionResult(
                url=submission.url,
                label=result['label'].upper(),
                confidence=result['confidence'],
                malicious_probability=result['malicious_probability'],
                benign_probability=result.get('benign_probability', 1.0 - result['malicious_probability']),
                status="analyzed"
            )
        
        except Exception as e:
            logger.error(f"Error scanning URL: {e}")
            REQUEST_COUNT.labels(status="error_processing").inc()
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/", tags=["Info"])
def read_root():
    """Get API status and available endpoints"""
    return {
        "message": "URL Scanner API is running",
        "version": "1.0.0",
        "endpoints": {
            "scan": {
                "method": "POST",
                "path": "/scan/",
                "description": "Scan a URL for malicious content"
            },
           "metrics": {
                "method": "GET",
                "path": "/metrics",
                "description": "Prometheus metrics"

            }
        },
        "ml_available": ML_AVAILABLE
    }
