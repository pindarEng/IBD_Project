from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import json
import logging
import sys
import os
from typing import Optional
from uuid import uuid4
from prometheus_client import make_asgi_app, Counter, Histogram
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.kafka_scripts import KafkaProducerService

# Load ML predictor
try:
    from ml_scripts.predictor import URLPredictor
    
    # Get absolute path to models directory
    SCRIPT_DIR = Path(__file__).parent.parent
    LIGHTWEIGHT_MODEL_PATH = str(SCRIPT_DIR / "models" / "random_forest_model.pkl")
    DEEP_MODEL_PATH = str(SCRIPT_DIR / "models" / "xgboost_model.pkl")
    
    logger = logging.getLogger(__name__)
    logger.info(f"Looking for models at: {LIGHTWEIGHT_MODEL_PATH}")
    logger.info(f"Looking for models at: {DEEP_MODEL_PATH}")
    
    # Check if model files exist
    if not Path(LIGHTWEIGHT_MODEL_PATH).exists():
        raise FileNotFoundError(f"Lightweight model not found at {LIGHTWEIGHT_MODEL_PATH}")
    if not Path(DEEP_MODEL_PATH).exists():
        raise FileNotFoundError(f"Deep model not found at {DEEP_MODEL_PATH}")
    
    predictor = URLPredictor(
        lightweight_model_path=LIGHTWEIGHT_MODEL_PATH,
        deep_model_path=DEEP_MODEL_PATH
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
    job_id: str = Field(..., description="Unique job ID for this submission")
    url: str = Field(..., description="The submitted URL")
    label: str = Field(..., description="Prediction label: BENIGN or MALICIOUS", example="MALICIOUS")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score (0.0 to 1.0)", example=0.5113)
    malicious_probability: float = Field(..., ge=0, le=1, description="Probability of malicious (0.0 to 1.0)", example=0.5113)
    benign_probability: Optional[float] = Field(None, ge=0, le=1, description="Probability of benign (0.0 to 1.0)", example=0.4887)
    status: str = Field(..., description="Status of the analysis", example="analyzed")
    message: str = Field(..., description="Human-readable message")


@app.post("/scan/", response_model=PredictionResult, tags=["URL Scanning"])
async def scan_url(submission: URLSubmission):
    """
    Scan a URL for malicious content.
    
    Dual processing:
    1. **Sync (API)**: Immediate ML prediction returned in response
    2. **Async (Worker)**: URL enqueued to Kafka for pipeline processing (expansion → features → prediction)
    
    The worker pipeline provides:
    - URL expansion (follow redirects, handle bot protection)
    - Additional monitoring and logging
    """
    with REQUEST_LATENCY.time():
        if not ML_AVAILABLE or predictor is None:
            REQUEST_COUNT.labels(status="error_ml_unavailable").inc()
            raise HTTPException(status_code=503, detail="ML models not loaded")

        try:
            job_id = str(uuid4())
            logger.info(f"[SCAN] Job ID: {job_id}")
            logger.info(f"[SCAN] Received URL: {submission.url}")
            
            # Get immediate prediction (sync)
            result = predictor.predict_single_url(submission.url, return_confidence=True)
            
            logger.info(f"[PREDICTION] Label: {result['label'].upper()}")
            logger.info(f"[PREDICTION] Confidence: {result['confidence']:.2%}")
            logger.info(f"[PREDICTION] Malicious Probability: {result['malicious_probability']:.2%}")
            
            if result['label'] == 'malicious':
                logger.warning(f"[ALERT] Malicious URL detected: {submission.url}")
            
            # Also enqueue to Kafka for async pipeline processing (expansion + features + prediction)
            if producer_service and producer_service.producer:
                try:
                    producer_service.send_url(KAFKA_TOPIC, submission.url)
                    logger.info(f"[SCAN] ✓ Also queued to worker pipeline for expansion → features → prediction")
                except Exception as kafka_err:
                    logger.warning(f"[SCAN] Failed to enqueue to Kafka (worker pipeline): {kafka_err}")
            else:
                logger.warning("[SCAN] Kafka producer not available; skipping worker pipeline")
            
            REQUEST_COUNT.labels(status="success").inc()

            return PredictionResult(
                job_id=job_id,
                url=submission.url,
                label=result['label'].upper(),
                confidence=result['confidence'],
                malicious_probability=result['malicious_probability'],
                benign_probability=result.get('benign_probability', 1.0 - result['malicious_probability']),
                status="analyzed",
                message="Immediate prediction from API. Worker pipeline also processing with URL expansion."
            )
        
        except Exception as e:
            logger.error(f"[SCAN] Error: {e}")
            REQUEST_COUNT.labels(status="error_processing").inc()
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/", tags=["Info"])
def read_root():
    """Get API status and available endpoints"""
    return {
        "message": "URL Scanner API is running",
        "version": "2.0.0",
        "processing": "Dual: Sync prediction (API) + Async pipeline (worker with URL expansion)",
        "endpoints": {
            "scan": {
                "method": "POST",
                "path": "/scan/",
                "description": "Scan a URL for malicious content",
                "response": "Immediate prediction + async worker pipeline processing"
            },
            "metrics": {
                "method": "GET",
                "path": "/metrics",
                "description": "Prometheus metrics"
            }
        },
        "processing_flow": {
            "sync": "Request → ML prediction → Response (immediate)",
            "async": "Enqueue to Kafka → Worker pipeline (expansion → features → prediction → logging)"
        },
        "ml_available": ML_AVAILABLE
    }
