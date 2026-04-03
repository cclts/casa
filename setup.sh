#!/usr/bin/env bash
set -e

echo "[+] Installing dependencies..."

sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    make \
    git \
    pkg-config

# install go
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    GO_ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    GO_ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

wget https://go.dev/dl/go1.22.5.linux-${GO_ARCH}.tar.gz

# cilium/ebpf dependency
echo "[+] Setting up Go modules..."
cd user
go mod init github.com/cclts/care-go
go get github.com/cilium/ebpf
go get github.com/cilium/ebpf/link
go get golang.org/x/sys

cd ..

echo "[+] Setup complete."