.PHONY: build run clean all test test-coverage help deps docker

.DEFAULT_GOAL := help

BINARY := RealiTLScanner

all: build ## Build the application (default)

build:
	go build -o $(BINARY) .

help: ## Show this help message
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: build ## Build and run (requires -addr, -in, or -url flag)
	@echo "Usage: ./$(BINARY) -addr <IP/CIDR/domain> [-port 443] [-thread 2] [-out out.csv]"
	@echo "       ./$(BINARY) -in <file> [-port 443] [-thread 2] [-out out.csv]"
	@echo "       ./$(BINARY) -url <url> [-port 443] [-thread 2] [-out out.csv]"

clean: ## Remove build artifacts
	rm -f $(BINARY)

deps: ## Download Go module dependencies
	go mod download

test: ## Run all tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage report (opens in browser)
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

docker: ## Build Docker image
	docker build -t $(BINARY) .
