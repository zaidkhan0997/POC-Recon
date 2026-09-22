#!/usr/bin/env bash
set -e

echo "=== Building POC-Recon (Pure Go Standalone Executable) ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

mkdir -p bin
go build -ldflags="-s -w" -o bin/poc-recon ./cmd/poc-recon

echo "=== Build Complete! ==="
echo "Binary created at: bin/poc-recon"
./bin/poc-recon --help
