CLANG := clang
BPFTOOL := bpftool
ARCH := arm64

EBPF_DIR := ebpf
EBPF_PROBES_DIR := $(EBPF_DIR)/probes
EBPF_HEADERS_DIR := $(EBPF_DIR)/headers
EBPF_BUILD_DIR := $(EBPF_DIR)/build

VMLINUX_H := $(EBPF_HEADERS_DIR)/vmlinux.h
C_SOURCES := $(wildcard $(EBPF_PROBES_DIR)/*.c)
BPF_OBJECTS := $(patsubst $(EBPF_PROBES_DIR)/%.c,$(EBPF_BUILD_DIR)/%.o,$(C_SOURCES))

BPF_FINAL := $(EBPF_BUILD_DIR)/probes.o

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(EBPF_HEADERS_DIR)

.PHONY: all vmlinux ebpf build run clean

all: vmlinux ebpf build

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@mkdir -p $(EBPF_HEADERS_DIR)
	@echo "Generating vmlinux.h..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

ebpf: $(BPF_FINAL)

$(BPF_FINAL): $(EBPF_PROBES_DIR)/main.c $(VMLINUX_H)
	@mkdir -p $(EBPF_BUILD_DIR)
	@echo "Compiling merged BPF object..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build:
	@echo "Building Go application..."
	go build -o user/app ./user/cmd/main.go

run: all
	@echo "Running application..."
	sudo ./user/app

clean:
	@echo "Cleaning up..."
	rm -rf $(EBPF_BUILD_DIR)