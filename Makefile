.PHONY: default format lint install check venv coverage

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

coverage coverage-skip-unsafe: export COVERAGE_PROCESS_START = $(PWD)/.coveragerc
coverage coverage-skip-unsafe: export COVERAGE_FILE = $(PWD)/.coverage
coverage:
	uv run coverage erase
	uv run coverage run --parallel-mode -m pytest
	uv run bash tests/shell/all.sh
	uv run bash tests/docker/0*.sh
	uv run bash tests/unsafe/0*.sh
	uv run coverage combine
	uv run coverage report --fail-under=40
	uv run coverage xml
coverage-skip-unsafe:
	uv run coverage erase
	uv run coverage run --parallel-mode -m pytest
	uv run bash tests/shell/all.sh
	uv run bash tests/docker/0*.sh
	uv run coverage combine
	uv run coverage report --fail-under=40
	uv run coverage xml
