# Kafka Pipeline Instructions

This folder contains the scripts for the Tiered Data Collection Pipeline using Apache Kafka.

## Prerequisites

1.  **Kafka Broker**: You need a running Kafka instance.
    *   If using Docker: `docker run -p 9092:9092 apache/kafka:latest`
2.  **Python Dependencies**:
    ```bash
    pip install kafka-python fastapi uvicorn
    ```

## 1. Producer (FastAPI)

This script exposes a REST API to accept URLs and pushes them to the Kafka topic `url_submission`.

**Run the Producer:**
```bash
uvicorn scripts.producer_api:app --reload
```
**use localhost:8000/docs**

## 2. Consumer (Worker)

This script listens to the `url_submission` topic and processes URLs based on the tiered logic:
*   **Expansion**: Expands short URLs (e.g., `bit.ly`).
*   **Fast Path**: Simple lexical analysis for normal URLs.
*   **Slow Path**: Deep analysis (WHOIS, DNS) for URLs with keywords like "bank", "payment".

**Run the Consumer:**
```bash
python scripts/consumer_worker.py
```
