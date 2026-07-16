set -e
set -x
uv run black --check cf_remote/*.py || true
uv run black --check tests/*.py || true
if [ -z "$1" ]; then
  uv run coverage run -m pytest
  uv run coverage html
else
  # for debugging, getting all output, and running a single test method:
  uv run pytest -k "$1" --show-capture=all -vv
fi
