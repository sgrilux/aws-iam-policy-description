# Makefile for AWS IAM Policy Description Tool

.PHONY: help install install-dev test test-unit test-integration test-slow test-coverage lint format type-check security-check docs-check pre-commit-install pre-commit-run clean all-checks

help:
	@echo "Available targets:"
	@echo "  install           - Install production dependencies"
	@echo "  install-dev       - Install development dependencies"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-integration  - Run integration tests only"
	@echo "  test-slow         - Run slow tests only"
	@echo "  test-coverage     - Run tests with coverage report"
	@echo "  lint              - Run linting checks"
	@echo "  format            - Format code with black and isort"
	@echo "  type-check        - Run type checking with mypy"
	@echo "  docs-check        - Check documentation coverage"
	@echo "  pre-commit-install - Install pre-commit hooks"
	@echo "  pre-commit-run    - Run pre-commit on all files"
	@echo "  all-checks        - Run all code quality checks"
	@echo "  clean             - Clean up generated files"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	pytest

test-unit:
	pytest -m unit

test-integration:
	pytest -m integration

test-slow:
	pytest -m slow

test-coverage:
	pytest --cov=. --cov-report=html --cov-report=term-missing

lint:
	flake8 *.py tests/

format:
	black *.py tests/
	isort *.py tests/

type-check:
	mypy *.py --no-strict-optional --ignore-missing-imports

docs-check:
	interrogate --quiet --fail-under=80 --ignore-nested-functions *.py

pre-commit-install:
	pre-commit install
	@echo "Pre-commit hooks installed successfully"

pre-commit-run:
	pre-commit run --all-files

all-checks: lint type-check docs-check test
	@echo "All code quality checks completed"

clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov .mypy_cache bandit-report.json
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
