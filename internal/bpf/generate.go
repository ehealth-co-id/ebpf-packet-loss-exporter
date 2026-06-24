package bpf

//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \"-O2 -g -Wall -I../../bpf/headers -I/usr/include/$(uname -m)-linux-gnu\" -target bpfel,bpfeb PacketLoss ../../bpf/packet_loss.bpf.c"
