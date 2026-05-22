# Compiler
CLANG := clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags for eBPF compilation
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -O2 -g

# Output directory
OUTPUT := .output
$(shell mkdir -p $(OUTPUT))

# Build socket tracker
$(OUTPUT)/socket_tracker.bpf.o: src/socket_tracker.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

all: $(OUTPUT)/socket_tracker.bpf.o

clean:
	rm -rf $(OUTPUT)

.PHONY: all clean