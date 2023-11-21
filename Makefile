update-deps:
	pip install --upgrade pip pip-tools
	pip-compile -v -o requirements.txt requirements.in

.PHONY: update-deps
