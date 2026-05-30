# Compiler
CLANG := clang
CC := gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Flags
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -O2 -g
USER_CFLAGS := -Wall -O2 -g
USER_LDFLAGS := -lbpf -lelf -lz

# Output directory
OUTPUT := .output
$(shell mkdir -p $(OUTPUT))

# Targets
BPF_OBJ := $(OUTPUT)/socket_tracker.bpf.o
USER_BIN := $(OUTPUT)/bandwidth_monitor

all: $(BPF_OBJ) $(USER_BIN)

# Compile eBPF program
$(BPF_OBJ): src/socket_tracker.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✓ Compiled eBPF program"

# Compile userspace program
$(USER_BIN): src/bandwidth_monitor.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "✓ Compiled userspace loader"

clean:
	rm -rf $(OUTPUT)

.PHONY: all clean