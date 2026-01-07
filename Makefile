.PHONY: up dev down build logs shell migrate createsuperuser

# Production
up:
	docker compose -f deploy/docker/compose.yml up -d

up-build:
	docker compose -f deploy/docker/compose.yml up -d --build

# Development
dev:
	docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.override.yml up

dev-build:
	docker compose -f deploy/docker/compose.yml -f deploy/docker/compose.override.yml up --build

# Stop
down:
	docker compose -f deploy/docker/compose.yml down

down-v:
	docker compose -f deploy/docker/compose.yml down -v

# Build
build:
	docker compose -f deploy/docker/compose.yml build

# Logs
logs:
	docker compose -f deploy/docker/compose.yml logs -f app

# Shell access
shell:
	docker compose -f deploy/docker/compose.yml exec app bash

# Django commands
migrate:
	docker compose -f deploy/docker/compose.yml exec app python manage.py migrate

createsuperuser:
	docker compose -f deploy/docker/compose.yml exec app python manage.py createsuperuser
