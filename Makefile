.PHONY: default format lint install check venv

default: check

venv:
	uv venv --clear
	uv sync

format: venv
	uv run black cf_remote/ tests/

lint: venv
	uv run black --check cf_remote/ tests/ --fast
	uv run flake8 cf_remote/ tests/ --ignore=E203,W503,E722,E731 --max-complexity=100 --max-line-length=160
	uv run pyflakes cf_remote/
	uv run pyright cf_remote/

install:
	pipx install --force --editable .

check: venv format lint
	uv run pytest
