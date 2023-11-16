# eBPF/XDP Test Example
A minimalistic and ready-to-use example of testing an eBPF/XDP program in pure C. The example is based on the work of https://who.ldelossa.is/posts/unit-testing-ebpf/, but I couldn't get it to work straight away. Enjoy!

## System Requirements (or well, tested on)
Ubuntu 22.04 LTS with kernel version 5.15.

## Dependencies
The main dependencies are `libxdp`, `libbpf`, `llvm`, `clang` and `libelf`. `LLVM` and `clang` compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (`libelf`), that is loaded by `libbpf` into the kernel via the `bpf` syscall. XDP programs are managed by `libxdp` which implements the XDP multi-dispatch protocol. Finally, the kernel headers are required for compilation of the program. Thanks [xdp-project](https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org)!

```sh
sudo apt install clang llvm libelf-dev libbpf-dev libpcap-dev build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump
```

## Usage
```sh
cd src
make
sudo ./test
```
