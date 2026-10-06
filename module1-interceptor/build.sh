#!/usr/bin/env bash

set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <name>"; exit 1; }

NAME="$1"

ARCH=$(uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

[ -f vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -g -O2 -target bpf -D__TARGET_ARCH_$ARCH -I. -c $NAME.bpf.c -o $NAME.bpf.o

bpftool gen skeleton $NAME.bpf.o > $NAME.skel.h

clang -g -O2 -Wall -I. $NAME.c -o $NAME -lbpf -lelf -lz

echo "built ./$NAME"


