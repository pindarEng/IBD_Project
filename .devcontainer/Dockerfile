FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir \
    numpy \
    pandas \
    matplotlib \
    scikit-learn \
    scipy \
    ipykernel \
    jupyter \
    notebook \
    seaborn \
    kafka-python \
    fastapi \
    uvicorn \
    python-whois \
    xgboost

WORKDIR /workspaces