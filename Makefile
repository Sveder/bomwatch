PY ?= .venv/bin/python
TEST_LINT_OFF = missing-module-docstring,missing-function-docstring

.PHONY: check format lint typecheck test integration install

install:
	$(PY) -m pip install -e '.[dev]'

format:
	$(PY) -m black src tests
	$(PY) -m ruff check --fix src tests

lint: typecheck
	$(PY) -m black --check src tests
	$(PY) -m ruff check src tests
	$(PY) -m pylint src/bomwatch
	$(PY) -m pylint --disable=$(TEST_LINT_OFF) tests

typecheck:
	$(PY) -m mypy

test:
	$(PY) -m pytest

# Installs a venv, a global npm package and a Node project, then diffs.
# Needs dpkg, npm and network; CI runs it in a Debian container.
integration:
	sh ci/integration.sh

check: lint test
