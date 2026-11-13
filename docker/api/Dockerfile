# syntax=docker/dockerfile:1
# Scoring API image. Build from the repository root:
#   docker build -f docker/api/Dockerfile -t ids-api .
#
# Two stages: the builder resolves the exact versions from uv.lock, the runtime image only gets the
# finished virtual environment (no uv, no compilers, no source tree) and runs as a non-root user.

FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

# Dependencies first: this layer is cached until uv.lock changes.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-default-groups --group api --no-install-project

COPY src ./src
RUN uv sync --locked --no-default-groups --group api --no-editable


FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# The model is baked in: one image = one immutable, testable model version.
# (Alternatively set MODEL_URI to load the @champion from the MLflow registry at startup.)
COPY params.yaml ./
COPY models/model.joblib ./models/model.joblib

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "ids.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
