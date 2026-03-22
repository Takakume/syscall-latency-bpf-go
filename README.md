# syscall-latency-bpf-go

A simple eBPF-based syscall latency tracer written in Go using `github.com/cilium/ebpf`.

Tested on:

- Amazon Linux 2023
- Kernel 6.1.x
- Go 1.22+

------------------------------------------------------------------------

## Overview

This program attaches to the following tracepoints:

- `tracepoint/raw_syscalls/sys_enter`
- `tracepoint/raw_syscalls/sys_exit`

It measures syscall latency per PID and prints:

- PID
- Count
- Average latency (us)
- Max latency (us)
- Selectable output format: `text`, `csv`, `json`

Example output:

    Running... Press Ctrl+C to stop.

    read
    ------------------------------------------------------------
    PID        COUNT      AVG(us)      MAX(us)
    1          80         2.01         13.67
    6018       16         4861628.39   77785998.06

------------------------------------------------------------------------

## Requirements

- Linux kernel 5.8+ (BTF recommended)
- Amazon Linux 2023 recommended
- clang / llvm
- Go 1.20+

Install dependencies (Amazon Linux 2023):

```bash
sudo dnf install -y clang llvm
```

------------------------------------------------------------------------

## Project Structure

    .
    |-- go.mod
    |-- go.sum
    |-- main.go
    `-- bpf/
        `-- syscall_latency.bpf.c

Generated files (not committed):

    *_bpfel.o
    *_bpfeb.o
    *_bpfel.go
    *_bpfeb.go

------------------------------------------------------------------------

## Build

### 1. Generate Go bindings from eBPF C program

```bash
go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -cc clang -cflags "-O2 -g -Wall" syscall bpf/syscall_latency.bpf.c -- -target bpf
```

### 2. Resolve dependencies

```bash
go mod tidy
```

### 3. Build binary

```bash
go build
```

------------------------------------------------------------------------

## Run

Root privileges are required to load eBPF programs:

```bash
sudo ./syscall-latency-bpf-go
```

You can also choose the output format:

```bash
sudo ./syscall-latency-bpf-go -output text
sudo ./syscall-latency-bpf-go -output csv
sudo ./syscall-latency-bpf-go -output json
```

Stop with `Ctrl+C` to display aggregated statistics.

------------------------------------------------------------------------

## Notes

- Uses `raw_syscalls` tracepoints (compatible with kernel 6.x)
- Works well on Amazon Linux 2023 (kernel 6.1)
- Designed for educational and observability experimentation

------------------------------------------------------------------------

## License

MIT (or specify your preferred license)
