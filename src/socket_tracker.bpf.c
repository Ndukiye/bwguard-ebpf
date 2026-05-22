// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


// MAP: Socket Pointer → PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // Hash map (like python dict)
    __type(key, u64);      // Socket pointer (as u64) (Key)
    __type(value, u32);    // PID (Value)
    __uint(max_entries, 10000); // Max size
} socket_pid_map SEC(".maps");


// HOOK: Track new TCP connections
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
    // Get current process PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;  // Upper 32 bits = PID
    
    // Store socket → PID mapping
    u64 sock_ptr = (u64)sk;
    bpf_map_update_elem(&socket_pid_map, &sock_ptr, &pid, BPF_ANY);
    
    // Debug: Print to kernel trace log
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("Tracked socket %llx for PID %d (%s)\n", sock_ptr, pid, comm);
    
    return 0;
}


// HOOK: Clean up when socket closes
SEC("kprobe/tcp_v4_destroy_sock")
int BPF_KPROBE(trace_tcp_destroy, struct sock *sk)
{
    u64 sock_ptr = (u64)sk;
    bpf_map_delete_elem(&socket_pid_map, &sock_ptr);
    
    bpf_printk("Removed socket %llx from tracking\n", sock_ptr);
    return 0;
}