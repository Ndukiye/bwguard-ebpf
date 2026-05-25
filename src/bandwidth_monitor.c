// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bandwidth_monitor.h"

// Global flag for clean shutdown
static volatile sig_atomic_t stop = 0;

// Signal handler
static void sig_handler(int sig) {
    stop = 1;
}

// Libbpf error callback (for debugging)
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int map_fd;
    int err;
    
    // Set up signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Set libbpf debug output
    libbpf_set_print(libbpf_print_fn);
    
    printf("Loading eBPF program...\n");
    
    // Open eBPF object file
    obj = bpf_object__open_file(".output/socket_tracker.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    // Load into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    printf("✓ eBPF program loaded\n");
    
    // Find the kprobe program
    prog = bpf_object__find_program_by_name(obj, "trace_tcp_connect");
    if (!prog) {
        fprintf(stderr, "Failed to find trace_tcp_connect program\n");
        goto cleanup;
    }
    
    // Attach kprobe
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe\n");
        goto cleanup;
    }
    
    printf("✓ Attached to tcp_v4_connect\n");
    
    // Get map file descriptor
    map_fd = bpf_object__find_map_fd_by_name(obj, "socket_pid_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find socket_pid_map\n");
        goto cleanup;
    }
    
    printf("\n=== Tracking TCP connections ===\n");
    printf("Press Ctrl+C to stop\n\n");
    
    // Main loop: Read map every 5 seconds
    while (!stop) {
        sleep(5);
        
        printf("\n--- Socket Map (entries: %d) ---\n", 
               bpf_map__max_entries(bpf_object__find_map_by_name(obj, "socket_pid_map")));
        
        __u64 key, next_key;
        __u32 value;
        
        // Iterate through map
        key = 0;
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("Socket 0x%llx → PID %u\n", next_key, value);
            }
            key = next_key;
        }
    }
    
cleanup:
    printf("\nCleaning up...\n");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    
    return 0;
}