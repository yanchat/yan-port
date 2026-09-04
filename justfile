set dotenv-load := false
set shell := ["bash", "-uc"]

default:
	@just --list

setup:
	uv sync --group dev

check:
	uv run ruff check .
	uv run pytest
	uv build

test:
	uv run pytest

format:
	uv run ruff format .

lint:
	uv run ruff check .

doctor:
	uv run yan-port doctor

install-caddy:
	sudo scripts/install-caddy-binary.sh

install-service:
	sudo scripts/install-service.sh
