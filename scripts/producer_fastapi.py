from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
import logging

from helper_functions.kafka_scripts import KafkaProducerService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Kafka Configuration
KAFKA_TOPIC = "url_submission"
KAFKA_BOOTSTRAP_SERVERS = "kafka:29092" # localhost daca vrei local da esti in devcontainer so ... # internal

# Initialize Producer (Global)
try:
    producer_service = KafkaProducerService(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
except Exception as e:
    logger.error(f"failed initialization for kafka producer: {e}")
    producer_service = None

class URLSubmission(BaseModel):
    url: str

@app.post("/scan/")
async def scan_url(submission: URLSubmission):
    if not producer_service or not producer_service.producer:
        raise HTTPException(status_code=503, detail="Kafka Producer not available")

    try:
        # Send message to Kafka
        result = producer_service.send_url(KAFKA_TOPIC, submission.url)
        
        logger.info(f"Sent URL to Kafka: {submission.url}")
        return {"status": "queued", "url": submission.url, "partition": result.partition, "offset": result.offset}
    except Exception as e:
        logger.error(f"Error sending to Kafka: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"message": "URL Scanner API is running. POST to /scan/ to submit URLs."}



#TODO: /metrics endpoint for prometheus and some dashboards in grafana.