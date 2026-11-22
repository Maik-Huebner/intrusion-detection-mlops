# MLflow tracking server with the exact MLflow version from uv.lock.
FROM python:3.12-slim

ENV MLFLOW_DISABLE_TELEMETRY=true \
    PIP_NO_CACHE_DIR=1
RUN pip install mlflow==3.17.2 && mkdir -p /mlflow/artifacts
WORKDIR /mlflow

EXPOSE 5000
# SQLite backend for runs and registry, artifacts (models, reports) proxied by the server.
# --allowed-hosts: MLflow rejects unknown Host headers (DNS rebinding protection). The API calls the
# server as http://mlflow:5000 inside the compose network, so that name is allowed next to localhost.
# --workers 2: the default of 4 needs over 2 GB RAM, which the local LLM needs more.
CMD ["mlflow", "server", \
     "--host", "0.0.0.0", \
     "--port", "5000", \
     "--workers", "2", \
     "--allowed-hosts", "mlflow:5000,localhost:*,127.0.0.1:*", \
     "--backend-store-uri", "sqlite:////mlflow/mlflow.db", \
     "--artifacts-destination", "/mlflow/artifacts", \
     "--serve-artifacts"]
