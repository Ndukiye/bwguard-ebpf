sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r) \
    make \
    gcc

    clang --version
    bpftool version