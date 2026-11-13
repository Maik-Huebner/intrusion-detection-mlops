# Common tasks. `make help` lists them.
.DEFAULT_GOAL := help
UV_RUN := uv run --env-file local.env

.PHONY: help setup data pipeline test lint format gate check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

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
