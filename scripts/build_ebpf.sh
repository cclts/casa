#!/usr/bin/env bash
set -e

mkdir -p ebpf/build

clang -O2 -g -target bpf \
  -c ebpf/probes/execve.c \
  -o ebpf/build/execve.o

clang -O2 -g -target bpf \
  -c ebpf/probes/openat.c \
  -o ebpf/build/openat.o

echo "[+] eBPF programs compiled."