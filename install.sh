#!/usr/bin/env bash
set -e

REPO="zaidkhan0997/POC-Recon"
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64)
        ARCH_NAME="x64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    *)
        echo "[!] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

if [ "$OS" = "linux" ]; then
    ASSET_NAME="poc-recon-linux-${ARCH_NAME}"
elif [ "$OS" = "darwin" ]; then
    ASSET_NAME="poc-recon-macos-${ARCH_NAME}"
else
    echo "[!] Unsupported operating system: $OS"
    exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
DEST="${INSTALL_DIR}/poc-recon"

echo "=== Installing POC-Recon ==="
echo "[*] Target OS: ${OS} (${ARCH_NAME})"
echo "[*] Downloading: ${DOWNLOAD_URL}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$DOWNLOAD_URL"
else
    echo "[!] Error: curl or wget is required to download POC-Recon."
    exit 1
fi

chmod +x "$DEST"

echo "[✔] Installed successfully to: ${DEST}"

# Add to PATH check
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo ""
    echo "[i] Note: Please add ${INSTALL_DIR} to your PATH by adding this line to ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
fi

echo "Run POC-Recon anytime using:"
echo "    poc-recon"
