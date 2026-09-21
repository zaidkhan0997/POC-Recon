#!/usr/bin/env bash
set -e

echo "=== Building POC-Recon Standalone Executable ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "[*] Installing dependencies..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt pyinstaller

echo "[*] Packaging with PyInstaller..."
.venv/bin/pyinstaller --clean -y poc-recon.spec

echo "=== Build Complete! ==="
echo "Binary created at: dist/poc-recon"
./dist/poc-recon --help
