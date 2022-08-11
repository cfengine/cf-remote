set -e
set -x
black --check cf_remote/*.py || true
black --check tests/*.py || true
if [ -z "$1" ]; then
  python3 -m coverage run -m pytest
  python3 -m coverage html
else
  # for debugging, getting all output, and running a single test method:
  python3 -m pytest -k "$1" --show-capture=all -vv
fi
