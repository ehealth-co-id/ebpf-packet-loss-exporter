.PHONY: all generate build test clean install

BINARY := ebpf_packet_loss_exporter
CMD := ./cmd/ebpf-packet-loss-exporter
INSTALL_DIR := /opt/ebpf_packet_loss_exporter

CLANG ?= clang
LLVM_STRIP ?= llvm-strip

all: generate build

generate:
	go generate ./internal/bpf/...

build: generate
	CGO_ENABLED=0 go build -o $(BINARY) $(CMD)

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -f internal/bpf/packetloss_*.go internal/bpf/packetloss_*.o

install: build
	install -d $(INSTALL_DIR)
	install -m 755 $(BINARY) $(INSTALL_DIR)/$(BINARY)

GOOS ?= linux
GOARCH ?= amd64

cross:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o $(BINARY) $(CMD)
