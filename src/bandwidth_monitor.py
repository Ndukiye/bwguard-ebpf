#!/usr/bin/env python3

import os
import time
import signal
import sys
import ctypes
from ctypes import c_uint32, c_uint64


# =========================
# Load libbpf
# =========================

libbpf = ctypes.CDLL("libbpf.so.1")


# =========================
# libbpf function signatures
# =========================

libbpf.bpf_object__open_file.argtypes = [
    ctypes.c_char_p,
    ctypes.c_void_p,
]
libbpf.bpf_object__open_file.restype = ctypes.c_void_p

libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]
libbpf.bpf_object__load.restype = ctypes.c_int

libbpf.bpf_object__find_map_by_name.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
]
libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p

libbpf.bpf_map__fd.argtypes = [ctypes.c_void_p]
libbpf.bpf_map__fd.restype = ctypes.c_int

libbpf.bpf_map_get_next_key.argtypes = [
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
libbpf.bpf_map_get_next_key.restype = ctypes.c_int

libbpf.bpf_map_lookup_elem.argtypes = [
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
libbpf.bpf_map_lookup_elem.restype = ctypes.c_int

# Program lookup
libbpf.bpf_object__find_program_by_name.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
]
libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p

# Program attach
libbpf.bpf_program__attach.argtypes = [ctypes.c_void_p]
libbpf.bpf_program__attach.restype = ctypes.c_void_p


# =========================
# BPF Map Wrapper
# =========================

class BPFMap:
    def __init__(self, map_fd):
        self.map_fd = map_fd

    def items(self):
        next_key = c_uint64()

        # Get first key
        ret = libbpf.bpf_map_get_next_key(
            self.map_fd,
            None,
            ctypes.byref(next_key)
        )

        if ret != 0:
            return

        current_key = next_key

        while True:
            value = c_uint32()

            ret = libbpf.bpf_map_lookup_elem(
                self.map_fd,
                ctypes.byref(current_key),
                ctypes.byref(value)
            )

            if ret == 0:
                yield (current_key.value, value.value)

            next_key = c_uint64()

            ret = libbpf.bpf_map_get_next_key(
                self.map_fd,
                ctypes.byref(current_key),
                ctypes.byref(next_key)
            )

            if ret != 0:
                break

            current_key = next_key


# =========================
# Socket Tracker
# =========================

class SocketTracker:

    def __init__(self, bpf_obj_path):
        self.bpf_obj_path = bpf_obj_path

        self.obj = None
        self.socket_pid_map = None

        self.connect_link = None
        self.destroy_link = None

        self.running = True
        self.last_sockets = set()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        print("\nStopping...")
        self.running = False

    def load(self):

        print(f"Loading BPF object: {self.bpf_obj_path}")

        self.obj = libbpf.bpf_object__open_file(
            self.bpf_obj_path.encode(),
            None
        )

        if not self.obj:
            raise Exception("Failed to open BPF object")

        err = libbpf.bpf_object__load(self.obj)

        if err != 0:
            raise Exception(f"Failed to load BPF object: {err}")

        print("✓ BPF object loaded")

        # =========================================
        # Attach trace_tcp_connect
        # =========================================

        connect_prog = libbpf.bpf_object__find_program_by_name(
            self.obj,
            b"trace_tcp_connect"
        )

        if not connect_prog:
            raise Exception("Could not find trace_tcp_connect")

        self.connect_link = libbpf.bpf_program__attach(connect_prog)

        if not self.connect_link:
            raise Exception("Failed to attach trace_tcp_connect")

        print("✓ Attached tcp_v4_connect probe")

        # =========================================
        # Attach trace_tcp_destroy
        # =========================================

        destroy_prog = libbpf.bpf_object__find_program_by_name(
            self.obj,
            b"trace_tcp_destroy"
        )

        if not destroy_prog:
            raise Exception("Could not find trace_tcp_destroy")

        self.destroy_link = libbpf.bpf_program__attach(destroy_prog)

        if not self.destroy_link:
            raise Exception("Failed to attach trace_tcp_destroy")

        print("✓ Attached tcp_close/tcp_destroy probe")

        # =========================================
        # Find map
        # =========================================

        map_obj = libbpf.bpf_object__find_map_by_name(
            self.obj,
            b"socket_pid_map"
        )

        if not map_obj:
            raise Exception("Failed to find socket_pid_map")

        map_fd = libbpf.bpf_map__fd(map_obj)

        if map_fd < 0:
            raise Exception("Failed to get map fd")

        self.socket_pid_map = BPFMap(map_fd)

        print("✓ Found socket_pid_map")

    def get_process_name(self, pid):
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return "<unknown>"

    def monitor(self, interval=1):

        print("\n=== Monitoring Socket Tracker ===")
        print("Generate network traffic to test")
        print("Press Ctrl+C to stop\n")

        while self.running:

            time.sleep(interval)

            current_sockets = {}

            try:
                for sock_ptr, pid in self.socket_pid_map.items():
                    current_sockets[sock_ptr] = pid

            except Exception as e:
                print(f"Map read error: {e}")
                continue

            current_set = set(current_sockets.keys())

            # =====================================
            # NEW SOCKETS
            # =====================================

            new_sockets = current_set - self.last_sockets

            for sock_ptr in new_sockets:
                pid = current_sockets[sock_ptr]
                proc_name = self.get_process_name(pid)

                print(
                    f"[+] NEW    "
                    f"Socket 0x{sock_ptr:x} "
                    f"→ PID {pid} ({proc_name})"
                )

            # =====================================
            # CLOSED SOCKETS
            # =====================================

            closed_sockets = self.last_sockets - current_set

            for sock_ptr in closed_sockets:
                print(
                    f"[-] CLOSED "
                    f"Socket 0x{sock_ptr:x}"
                )

            # =====================================
            # ACTIVE SOCKETS
            # =====================================

            print(f"\n[ACTIVE] {len(current_sockets)} sockets")

            for sock_ptr, pid in current_sockets.items():

                proc_name = self.get_process_name(pid)

                print(
                    f"  Socket 0x{sock_ptr:x} "
                    f"→ PID {pid} ({proc_name})"
                )

            print()

            self.last_sockets = current_set


# =========================
# Main
# =========================

def main():

    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

    bpf_obj_path = ".output/socket_tracker.bpf.o"

    if not os.path.exists(bpf_obj_path):
        print(f"Missing: {bpf_obj_path}")
        print("Run: make")
        sys.exit(1)

    tracker = SocketTracker(bpf_obj_path)

    try:
        tracker.load()
        tracker.monitor(interval=1)

    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()