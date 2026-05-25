// SPDX-License-Identifier: GPL-2.0
#ifndef __BANDWIDTH_MONITOR_H
#define __BANDWIDTH_MONITOR_H

// Map definitions (must match eBPF side)
struct socket_pid_entry {
    __u64 sock_ptr;
    __u32 pid;
};

#endif /* __BANDWIDTH_MONITOR_H */