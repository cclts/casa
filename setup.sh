#!/usr/bin/env bash
set -e

echo "[+] Installing dependencies..."

# 基本工具
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    gcc-multilib \
    make \
    git \
    pkg-config

# Go 安裝（如果沒有）
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz

    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# cilium/ebpf dependency
echo "[+] Setting up Go modules..."
cd user
go mod init openclaw
go get github.com/cilium/ebpf
go get github.com/cilium/ebpf/link
go get golang.org/x/sys

cd ..

echo "[+] Setup complete."