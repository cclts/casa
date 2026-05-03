#!/usr/bin/env bash
set -euo pipefail

GO_VERSION="1.24.0"
OPENCLAW_BASELINE_VERSION="2026.3.24 (cff6dc9)"
MODULE_NAME="github.com/cclts/casa" 
REQUIRED_PKGS=(
  build-essential clang llvm libelf-dev libbpf-dev 
  linux-headers-$(uname -r) bpftool make git curl wget pkg-config
)

echo "[+] Step 1: Installing System Dependencies..."
sudo apt update
sudo apt install -y "${REQUIRED_PKGS[@]}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)       GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *) echo "[-] Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

if ! command -v go >/dev/null 2>&1; then
  echo "[+] Installing Go ${GO_VERSION}..."
  TMP_TAR="/tmp/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  
  wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O "$TMP_TAR"
  
  sudo tar -C /usr/local -xzf "$TMP_TAR"
  rm "$TMP_TAR"

  export PATH="/usr/local/go/bin:$PATH"
  
  if ! grep -Fq '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
  echo "[+] Go installed to /usr/local/go"
else
  CURRENT_GO_VERSION="$(go version)"
  if [[ "$CURRENT_GO_VERSION" != *"go${GO_VERSION}"* ]]; then
    echo "[!] Warning: expected Go ${GO_VERSION}, found: ${CURRENT_GO_VERSION}"
    echo "[!] Please install Go ${GO_VERSION} if build issues occur."
  else
    echo "[+] Go ${GO_VERSION} is already installed."
  fi
fi

echo "[+] Step 2: Preparing Go module..."

if [ ! -f "go.mod" ]; then
  go mod init "$MODULE_NAME"
else
  echo "[+] go.mod already exists"
fi
go mod tidy

echo "[+] Step 3: Creating runtime directories..."
mkdir -p ebpf/build ebpf/headers user/logs

echo "[+] Step 4: Checking OpenClaw prerequisites..."
if command -v openclaw >/dev/null 2>&1; then
  OPENCLAW_VERSION="$(openclaw --version 2>/dev/null || true)"
  if [[ -n "$OPENCLAW_VERSION" ]]; then
    echo "[+] Found OpenClaw: $OPENCLAW_VERSION"
    if [[ "$OPENCLAW_VERSION" != *"$OPENCLAW_BASELINE_VERSION"* ]]; then
      echo "[!] Warning: validated baseline is OpenClaw $OPENCLAW_BASELINE_VERSION"
    fi
  else
    echo "[!] Warning: OpenClaw is installed but version could not be read."
  fi
else
  echo "[!] Warning: OpenClaw CLI not found."
  echo "[!] CASA evaluation requires OpenClaw to be installed separately."
fi

echo "--------------------------------------"
echo "[+] Setup successful!"
echo "[!] Please run: 'source ~/.bashrc' or add /usr/local/go/bin to your PATH"
echo "[!] Before running evaluation, make sure:"
echo "    1. OpenClaw is installed"
echo "    2. OpenClaw onboarding is completed"
echo "    3. A working LLM provider/API key is configured for OpenClaw"
echo "[+] Build command: make all"
