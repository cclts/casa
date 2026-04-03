#!/usr/bin/env bash
set -e

echo "[+] Building eBPF..."
./scripts/build_ebpf.sh

echo "[+] Running user space..."
cd user
sudo go run ./cmd/main.go