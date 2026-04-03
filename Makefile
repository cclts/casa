.PHONY: all ebpf run clean

all: ebpf build

ebpf:
	./scripts/build_ebpf.sh

build:
	cd user && go build -o app ./cmd

run: ebpf
	cd user && sudo ./app

clean:
	rm -rf ebpf/build
	rm -f user/app