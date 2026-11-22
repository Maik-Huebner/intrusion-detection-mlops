# Common tasks. `make help` lists them.
.DEFAULT_GOAL := help
UV_RUN := uv run --env-file local.env
COMPOSE := docker compose --env-file local.env
# Registry commands talk to the MLflow server of the compose stack.
REGISTRY := MLFLOW_TRACKING_URI=http://127.0.0.1:5050 $(UV_RUN)

# Retraining scenario: Thursday's traffic has been labelled, the model learns it.
RETRAIN_DAYS := [monday,tuesday,wednesday,thursday]
RETRAIN_FUTURE := [friday]

.PHONY: help setup data pipeline test lint format gate check \
        stack stop llm register retrain rollout rollback replay demo evaluate-api evaluate-llm

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

# --- Development -----------------------------------------------------------------------------------
setup: ## Create the virtual environment from uv.lock
	uv sync --locked

data: ## Download and verify the raw dataset (328 MB)
	$(UV_RUN) python -m ids.data.download

pipeline: ## Run the DVC pipeline (only stages whose inputs changed)
	$(UV_RUN) dvc repro

test: ## Run the unit tests
	$(UV_RUN) pytest

lint: ## Lint and check formatting
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .

format: ## Auto-format the code
	$(UV_RUN) ruff format .
	$(UV_RUN) ruff check --fix .

gate: ## Quality gate on the current metrics
	$(UV_RUN) python -m ids.quality_gate

check: lint test ## Everything CI checks before the pipeline

# --- Operations (compose stack) --------------------------------------------------------------------
stack: ## Start MLflow, API, Prometheus and Grafana
	$(COMPOSE) up -d --build

stop: ## Stop the stack (data in the volumes is kept)
	$(COMPOSE) down

llm: ## Download the LLM for the analyst notes into the Ollama volume (once, about 2 GB)
	$(COMPOSE) exec ollama ollama pull llama3.2:3b

register: ## Log the current pipeline result to MLflow and run champion/challenger
	$(REGISTRY) python -m ids.registry log
	$(REGISTRY) python -m ids.registry promote

retrain: ## Retrain with Thursday as a DVC experiment, register and promote it
	$(UV_RUN) dvc exp run -n retrain-with-thursday --force \
		-S 'split.train_days=$(RETRAIN_DAYS)' -S 'split.future_days=$(RETRAIN_FUTURE)'
	$(MAKE) register

rollout: ## Restart the API so it loads the current @champion
	$(COMPOSE) restart api

rollback: ## Point @champion to an older version and roll it out: make rollback V=1
	$(REGISTRY) python -m ids.registry champion $(V)
	$(MAKE) rollout

replay: ## Replay a capture day against the API: make replay DAY=thursday
	$(UV_RUN) python -m ids.replay $(DAY)

demo: ## Full live demo: make demo BEFORE=1 AFTER=2 (registry versions)
	$(REGISTRY) python -m ids.demo --before $(BEFORE) --after $(AFTER)

evaluate-api: ## Latency, throughput, robustness and quality of the running API
	$(REGISTRY) python -m ids.evaluate_api

evaluate-llm: ## Rule pass rate, fallbacks and latency of the analyst notes (logged to MLflow)
	$(REGISTRY) python -m ids.evaluate_llm
