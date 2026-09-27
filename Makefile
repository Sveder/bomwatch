PY ?= .venv/bin/python
TEST_LINT_OFF = missing-module-docstring,missing-function-docstring

.PHONY: check format lint test install

install:
	$(PY) -m pip install -e '.[dev]'

format:
	$(PY) -m black src tests

lint:
	$(PY) -m black --check src tests
	$(PY) -m pylint src/bomwatch
	$(PY) -m pylint --disable=$(TEST_LINT_OFF) tests

test:
	$(PY) -m pytest

check: lint test
