.PHONY: up up-build dev dev-build down down-v build logs shell migrate test lint lock issue-cert

# All compose state lives in deploy/docker: compose files, .env, and the overlays
# that bootstrap.sh selects via COMPOSE_FILE.
COMPOSE_DIR := deploy/docker
COMPOSE     := docker compose
BOOTSTRAP   := $(COMPOSE_DIR)/bootstrap.sh

# Production ------------------------------------------------------------------
up:
	cd $(COMPOSE_DIR) && $(COMPOSE) up -d

up-build:
	cd $(COMPOSE_DIR) && $(COMPOSE) up -d --build

# Development -----------------------------------------------------------------
dev:
	cd $(COMPOSE_DIR) && $(COMPOSE) -f compose.yml -f compose.dev.yml up

dev-build:
	cd $(COMPOSE_DIR) && $(COMPOSE) -f compose.yml -f compose.dev.yml up --build

# Lifecycle -------------------------------------------------------------------
down:
	cd $(COMPOSE_DIR) && $(COMPOSE) down

down-v:
	@echo "WARNING: this deletes the database volume and every stored key."
	cd $(COMPOSE_DIR) && $(COMPOSE) down -v

build:
	cd $(COMPOSE_DIR) && $(COMPOSE) build

logs:
	cd $(COMPOSE_DIR) && $(COMPOSE) logs -f app

shell:
	cd $(COMPOSE_DIR) && $(COMPOSE) exec app bash

migrate:
	cd $(COMPOSE_DIR) && $(COMPOSE) exec app python manage.py migrate

# Have Pemly's own CA issue the web UI certificate, then reload the proxy.
issue-cert:
	$(BOOTSTRAP) issue-cert

# Quality ---------------------------------------------------------------------
test:
	cd $(COMPOSE_DIR) && $(COMPOSE) run --rm --no-deps --entrypoint "" \
		-v $(CURDIR):/app -e DJANGO_SETTINGS_MODULE=pkife.settings.testing \
		app python -m pytest

lint:
	docker run --rm -v $(CURDIR):/w -w /w ghcr.io/astral-sh/ruff:latest check .

# Recompile the dependency locks from requirements.in / requirements-dev.in.
# Run this after editing either .in file, and commit the generated .txt files;
# they carry exact versions and hashes, and nothing else installs dependencies.
# --python-version 3.11 keeps the lock valid on the oldest interpreter we claim
# to support, while --universal keeps it valid on a Linux image and a macOS
# development machine from the same file.
lock:
	uv pip compile requirements.in --universal --generate-hashes \
		--python-version 3.11 -o requirements.txt
	uv pip compile requirements-dev.in --universal --generate-hashes \
		--python-version 3.11 -o requirements-dev.txt
