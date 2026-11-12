# Farrier event functions. Everything here works offline.
PYTHON ?= python3

.PHONY: test build clean

test:
	cd .. && $(PYTHON) -m pytest -q functions

build:
	$(PYTHON) tools/package.py all

clean:
	rm -rf dist
