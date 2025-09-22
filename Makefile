# SPDX-License-Identifier: GPL-3.0-only
# Copyright 2025 RH America LLC <info@rhamerica.com>

# Makefile for BGP - Cryptographic Library and CLI Tool

.PHONY: help build build-cli clean test fmt vet install deps lint all goimports integration-test ci

# Default target
all: clean fmt vet test build

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Run clean, fmt, vet, test, and build"
	@echo "  build        - Build both CLI"
	@echo "  build-cli    - Build the CLI tool"
	@echo "  clean        - Remove built binaries and temporary files"
	@echo "  test         - Run tests"
	@echo "  fmt          - Format Go code"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run golangci-lint (if available)"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  install      - Install CLI tool to GOPATH/bin"
	@echo "  demo         - Run a quick demo of the CLI"

# Build targets
build: build-cli

build-cli:
	@echo "Building CLI tool..."
	go build -o bgp ./cmd


# Clean target
clean:
	@echo "Cleaning up..."
	rm -f bgp
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

goimports:
	@echo "Checking goimports (no changes allowed)..."
	@# Ensure goimports is installed (install unconditionally to guarantee availability)
	@go install golang.org/x/tools/cmd/goimports@latest
	@# Run goimports in a subshell and fail if any files would change
	@sh -c 'if [ -n "$$(goimports -l .)" ]; then echo "goimports found issues:"; goimports -l .; exit 1; fi'

vet:
	@echo "Running go vet..."
	go vet ./...

lint:
	@echo "Running linter..."
	@# Ensure golangci-lint is installed (install unconditionally to guarantee availability)
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Running golangci-lint..."
	@golangci-lint run

integration-test:
	@echo "Running integration tests (builds binary and runs integration package tests)..."
	go build -o bgp ./cmd
	go test ./integration -run TestEndToEnd -v

ci: fmt goimports vet lint test build
	@echo "CI pipeline finished successfully"

# Dependency management
deps:
	@echo "Downloading and tidying dependencies..."
	go mod download
	go mod tidy


# Installation target
install:
	@echo "Installing bgp CLI tool..."
	# Build the CLI and install to GOBIN, GOPATH/bin or /usr/local/bin
	go build -trimpath -o bgp ./cmd
	@sh -c 'GOPATH=$$(go env GOPATH); if [ -n "$$GOPATH" ]; then mkdir -p "$$GOPATH/bin" && mv bgp "$$GOPATH/bin" && echo "Installed bgp to $$GOPATH/bin"; else sudo mv bgp /usr/local/bin && echo "Installed bgp to /usr/local/bin"; fi'


demo: build-cli
	@echo "Running CLI demo..."
	@echo "1. Generating keys in default keystore (~/.bgp/keystore)..."
	@./bgp keygen -name demo -email demo@example.com
	@echo ""
	@echo "2. Listing keys..."
	@./bgp list
	@echo ""
	@echo "3. Encrypting and decrypting a message..."
	@echo "Hello from Makefile demo!" | ./bgp encrypt -to demo -from demo@example.com | ./bgp decrypt
	@echo ""
	@echo "Demo complete! Keys are stored in ~/.bgp/keystore"

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
	CGO_ENABLED=0 go build -ldflags="-w -s" -o bgp ./cmd
	@echo "Release build complete: ./bgp"

# Quick build for development
quick: 
	go build -o bgp ./cmd

# Check everything is working
check: build test
	@echo "All checks passed!"
