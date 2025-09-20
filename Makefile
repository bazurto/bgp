# Makefile for BPG - Cryptographic Library and CLI Tool

.PHONY: help build build-cli build-examples clean test fmt vet install deps run-example lint all

# Default target
all: clean fmt vet test build

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Run clean, fmt, vet, test, and build"
	@echo "  build        - Build both CLI and examples"
	@echo "  build-cli    - Build the CLI tool"
	@echo "  build-examples - Build example programs"
	@echo "  clean        - Remove built binaries and temporary files"
	@echo "  test         - Run tests"
	@echo "  fmt          - Format Go code"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run golangci-lint (if available)"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  install      - Install CLI tool to GOPATH/bin"
	@echo "  run-example  - Run the library example"
	@echo "  demo         - Run a quick demo of the CLI"

# Build targets
build: build-cli build-examples

build-cli:
	@echo "Building CLI tool..."
	go build -o bpg ./cmd

build-examples:
	@echo "Building examples..."
	cd examples/library && go build -o library_example

# Clean target
clean:
	@echo "Cleaning up..."
	rm -f bpg
	rm -f examples/library/library_example
	rm -f encrypted_message.json
	go clean

# Test target
test:
	@echo "Running tests..."
	go test ./...

# Code quality targets
fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping..."; \
	fi

# Dependency management
deps:
	@echo "Downloading and tidying dependencies..."
	go mod download
	go mod tidy

# Installation target
install:
	@echo "Installing bpg CLI tool..."
	go install ./cmd

# Demo and example targets
run-example: build-examples
	@echo "Running library example..."
	cd examples/library && ./library_example

demo: build-cli
	@echo "Running CLI demo..."
	@echo "1. Generating keys..."
	@./bpg keygen -name demo -email demo@example.com
	@echo ""
	@echo "2. Listing keys..."
	@./bpg list-keys
	@echo ""
	@echo "3. Encrypting and decrypting a message..."
	@echo "Hello from Makefile demo!" | ./bpg encrypt -to demo -from demo@demo@example.com | ./bpg decrypt
	@echo ""
	@echo "Demo complete!"

# Development targets
dev-setup: deps
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi

# Release build (with optimizations)
release: clean fmt vet test
	@echo "Building release version..."
	CGO_ENABLED=0 go build -ldflags="-w -s" -o bpg ./cmd
	@echo "Release build complete: ./bpg"

# Quick build for development
quick: 
	go build -o bpg ./cmd

# Check everything is working
check: build test run-example
	@echo "All checks passed!"
