VENV = venv
export PATH := $(VENV)/bin:$(VENV)/Scripts:$(PATH)

all: help

venv:
	python3 -m venv "$(VENV)"
	pip install --upgrade pip

rmenv:
	rm -rf "$(VENV)"

dev setup: venv
	pip install -e .[dev]

test:
	pytest

coverage cov:
	pytest --cov

build: wheel sdist

wheel sdist:
	python -m build --$@

clean:
	rm -rf build .coverage dist .eggs .pytest_cache .pytype .mypy_cache *.log
	find . -name __pycache__ -delete

reallyclean: clean

distclean: reallyclean rmenv
	rm -rf *.egg-info


help:
	@echo "Setup:"
	@echo "  > make dev"
	@echo
	@echo "Setup targets:"
	@echo "  dev            install extras for development"
	@echo "  venv           create virtual environment and upgrade pip"
	@echo
	@echo "Test targets:"
	@echo "  cov, coverage  run unit tests with coverage"
	@echo "  test           run unit tests"
	@echo
	@echo "Cleaning:"
	@echo "  clean          remove build files and temporary data"
	@echo "  reallyclean    clean more"
	@echo "  distclean      remove everything not part of the distribution"
	@echo "  rmenv          remove virtual environment"
	@echo
	@echo "Build targets:"
	@echo "  build, wheel, sdist"
