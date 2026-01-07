.PHONY: up dev down build logs shell migrate createsuperuser

COMPOSE := docker compose --env-file .env -f deploy/docker/compose.yml

# Production
up:
	$(COMPOSE) up -d

up-build:
	$(COMPOSE) up -d --build

# Development
dev:
	$(COMPOSE) -f deploy/docker/compose.override.yml up

dev-build:
	$(COMPOSE) -f deploy/docker/compose.override.yml up --build

# Stop
down:
	$(COMPOSE) down

down-v:
	$(COMPOSE) down -v

# Build
build:
	$(COMPOSE) build

# Logs
logs:
	$(COMPOSE) logs -f app

# Shell access
shell:
	$(COMPOSE) exec app bash

# Django commands
migrate:
	$(COMPOSE) exec app python manage.py migrate

createsuperuser:
	$(COMPOSE) exec app python manage.py createsuperuser
