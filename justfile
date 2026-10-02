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

router-install:
	uv run yan-port router install

router-start:
	uv run yan-port router start

router-stop:
	uv run yan-port router stop

router-uninstall *args:
	uv run yan-port router uninstall {{args}}

trust-install:
	uv run yan-port trust install

trust-remove:
	uv run yan-port trust remove --yes

install-caddy:
	sudo scripts/install-caddy-binary.sh

install-service:
	sudo scripts/install-service.sh
