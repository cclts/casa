CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go
PRESERVE_ENV := CASA_RULES_PATH,CASA_EVENTS_LOG_PATH,CASA_LATENCY_TRACE_PATH,CASA_SESSIONS_LOG_PATH,CASA_AUDIT_LOG_PATH,CASA_ALERT_LOG_PATH,CASA_BPF_PATH,CASA_PID_PATH,CASA_DEBUG_EVAL

UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
ARCH := x86
else ifeq ($(UNAME_M),aarch64)
ARCH := arm64
else ifeq ($(UNAME_M),arm64)
ARCH := arm64
else
$(error Unsupported architecture: $(UNAME_M))
endif

EBPF_DIR := ebpf
EBPF_PROBES_DIR := $(EBPF_DIR)/probes
EBPF_HEADERS_DIR := $(EBPF_DIR)/headers
EBPF_BUILD_DIR := $(EBPF_DIR)/build

VMLINUX_H := $(EBPF_HEADERS_DIR)/vmlinux.h
BPF_FINAL := $(EBPF_BUILD_DIR)/probes.o

USER_DIR := user
GO_APP := $(USER_DIR)/app
GO_MAIN := ./cmd/main.go

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(EBPF_HEADERS_DIR)

.PHONY: all setup check-deps vmlinux ebpf build run clean distclean

all: check-deps vmlinux ebpf build

setup:
	./setup.sh

check-deps:
	@command -v $(CLANG) >/dev/null || (echo "missing clang"; exit 1)
	@command -v $(BPFTOOL) >/dev/null || (echo "missing bpftool"; exit 1)
	@command -v $(GO) >/dev/null || (echo "missing go"; exit 1)
	@test -r /sys/kernel/btf/vmlinux || (echo "missing /sys/kernel/btf/vmlinux"; exit 1)

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@mkdir -p $(EBPF_HEADERS_DIR)
	@echo "[+] Generating vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

ebpf: $(BPF_FINAL)

$(BPF_FINAL): $(EBPF_PROBES_DIR)/main.c $(VMLINUX_H)
	@mkdir -p $(EBPF_BUILD_DIR)
	@echo "[+] Compiling merged BPF object for $(ARCH)"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build:
	@echo "[+] Building Go application"
	cd $(USER_DIR) && $(GO) mod tidy
	cd $(USER_DIR) && $(GO) build -o app $(GO_MAIN)

run: all
	@echo "[+] Running application ..."
	sudo --preserve-env=$(PRESERVE_ENV) ./$(GO_APP)

clean:
	@echo "[+] Cleaning build artifacts"
	rm -rf $(EBPF_BUILD_DIR)
	rm -f $(GO_APP)

distclean: clean
	@echo "[+] Removing generated headers"
	rm -f $(VMLINUX_H)
