# MLflow tracking server with the exact MLflow version from uv.lock.
FROM python:3.12-slim

ENV MLFLOW_DISABLE_TELEMETRY=true \
    PIP_NO_CACHE_DIR=1
RUN pip install mlflow==3.17.2 && mkdir -p /mlflow/artifacts
WORKDIR /mlflow

EXPOSE 5000
# SQLite backend for runs and registry, artifacts (models, reports) proxied by the server.
CMD ["mlflow", "server", \
     "--host", "0.0.0.0", \
     "--port", "5000", \
     "--backend-store-uri", "sqlite:////mlflow/mlflow.db", \
     "--artifacts-destination", "/mlflow/artifacts", \
     "--serve-artifacts"]
