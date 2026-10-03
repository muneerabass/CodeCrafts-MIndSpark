.PHONY: build test vet dev-db dev-api dev-worker dev-web up down logs

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

# Local dev Postgres + Mailpit (passwords are dev-only)
dev-db:
	@if docker inspect depguard-dev-pg >/dev/null 2>&1; then \
		docker start depguard-dev-pg >/dev/null 2>&1 || true; \
	else \
		docker run -d --name depguard-dev-pg -p $(DEV_DB_PORT):5432 \
		  -e POSTGRES_USER=depguard -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=depguard \
		  -e DEPGUARD_APP_PASSWORD=dev -e DEPGUARD_QUERY_PASSWORD=dev -e DEPGUARD_WEB_PASSWORD=dev \
		  -v $(CURDIR)/deploy/postgres/init.sh:/docker-entrypoint-initdb.d/10-init.sh:ro postgres:17; \
	fi
	@if docker inspect depguard-dev-mail >/dev/null 2>&1; then \
		docker start depguard-dev-mail >/dev/null 2>&1 || true; \
	else \
		docker run -d --name depguard-dev-mail -p 8025:8025 -p 1025:1025 axllent/mailpit; \
	fi

DEV_DB_PORT ?= 5432
DEV_API_PORT ?= 8080
DEV_WORKER_HEALTH_PORT ?= 8081

DEV_ENV = DATABASE_URL=postgres://depguard_app:dev@localhost:$(DEV_DB_PORT)/depguard?sslmode=disable \
  DATABASE_OWNER_URL=postgres://depguard:dev@localhost:$(DEV_DB_PORT)/depguard?sslmode=disable \
  DATABASE_QUERY_URL=postgres://depguard_query:dev@localhost:$(DEV_DB_PORT)/depguard?sslmode=disable \
  SERVICE_JWT_SECRET=dev-only-service-jwt-secret-0123456789abcdef PUBLIC_URL=http://localhost:3000 \
  PUBLIC_API_URL=http://localhost:$(DEV_API_PORT) TENANT_DOMAIN_SUFFIX=localhost

dev-api:
	$(DEV_ENV) HTTP_ADDR=:$(DEV_API_PORT) go run ./cmd/api

dev-worker:
	$(DEV_ENV) WORKER_HEALTH_ADDR=:$(DEV_WORKER_HEALTH_PORT) go run ./cmd/worker

dev-web:
	cd web && pnpm dev

# Production (single host)
up:
	cd deploy && docker compose --env-file .env up -d --build
down:
	cd deploy && docker compose --env-file .env down
logs:
	cd deploy && docker compose --env-file .env logs -f --tail=200
