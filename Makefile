BINARY_NAME=poc-recon
BIN_DIR=bin
CMD_DIR=./cmd/poc-recon

.PHONY: all build test clean run install cross-compile tidy

all: test build

build:
	@mkdir -p $(BIN_DIR)
	@echo "==> Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "==> Build complete: $(BIN_DIR)/$(BINARY_NAME)"

install:
	@echo "==> Installing $(BINARY_NAME) to $(GOPATH)/bin..."
	go install $(CMD_DIR)

test:
	@echo "==> Running unit tests..."
	go test -v ./...

tidy:
	@echo "==> Tidying dependencies..."
	go mod tidy

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) results/test_*

cross-compile:
	@mkdir -p $(BIN_DIR)/release
	@echo "==> Building Linux amd64..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/release/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	@echo "==> Building Linux arm64..."
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN_DIR)/release/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	@echo "==> Building macOS amd64..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/release/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	@echo "==> Building macOS arm64..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN_DIR)/release/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	@echo "==> Building Windows amd64..."
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/release/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "==> Cross-compilation complete! Binaries in $(BIN_DIR)/release/"
