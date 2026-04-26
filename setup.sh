#!/usr/bin/env bash
set -euo pipefail

GO_VERSION="1.22.5"
MODULE_NAME="github.com/cclts/care-go" 
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

if ! command -v go >/dev/null 2>&1 || [[ "$(go version)" != *"$GO_VERSION"* ]]; then
  echo "[+] Installing Go ${GO_VERSION}..."
  TMP_TAR="/tmp/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  
  wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O "$TMP_TAR"
  
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$TMP_TAR"
  rm "$TMP_TAR"

  export PATH="/usr/local/go/bin:$PATH"
  
  echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
  echo "[+] Go installed to /usr/local/go"
else
  echo "[+] Go $GO_VERSION is already installed."
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

echo "--------------------------------------"
echo "[+] Setup successful!"
echo "[!] Please run: 'source ~/.bashrc' or add /usr/local/go/bin to your PATH"
echo "[+] Now you can run: 'make all'"