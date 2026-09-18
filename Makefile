.PHONY: help build test clippy fmt clean install-deps lab-up lab-down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build debug version
	cargo build

build-release: ## Build optimized release version
	cargo build --release

test: ## Run all tests
	cargo test

test-unit: ## Run unit tests only
	cargo test --lib

test-integration: ## Run integration tests only
	cargo test --test integration

test-e2e: ## Run E2E tests only
	cargo test --test e2e

clippy: ## Run clippy linter
	cargo clippy -- -D warnings

fmt: ## Check formatting
	cargo fmt --check

fmt-fix: ## Fix formatting
	cargo fmt

clean: ## Clean build artifacts
	cargo clean

install-deps: ## Install required external tools
	@echo "Installing sqlmap..."
	pip install sqlmap
	@echo "Installing dalfox..."
	cargo install dalfox
	@echo "Installing ssrfmap..."
	git clone https://github.com/swisskyrepo/ssrfmap.git /tmp/ssrfmap
	cd /tmp/ssrfmap && pip install -r requirements.txt
	@echo "Installing npm audit..."
	npm install -g npm
	@echo "Installing pip-audit..."
	pip install pip-audit
	@echo "Installing cargo-audit..."
	cargo install cargo-audit
	@echo "All dependencies installed!"

check-tools: build ## Check if all tools are installed
	cargo run -- check-tools

init-config: build ## Generate default config file
	cargo run -- init-config

lab-up: ## Start lab environments
	docker-compose -f lab/docker-compose.yml up -d

lab-down: ## Stop lab environments
	docker-compose -f lab/docker-compose.yml down

scan-dvwa: build ## Scan DVWA (requires lab-up)
	cargo run -- scan --target http://localhost:80/dvwa --checks all

scan-juice: build ## Scan OWASP Juice Shop (requires lab-up)
	cargo run -- scan --target http://localhost:3000 --checks all

record: build ## Record a browser session
	cargo run -- record --output session.har

version: ## Show version
	cargo run -- version
