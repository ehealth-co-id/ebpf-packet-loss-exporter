package bpf

import (
	"net"
	"testing"
)

func TestLpmKeyFromNetEndianness(t *testing.T) {
	_, n, err := net.ParseCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	key := lpmKeyFromNet(*n)
	if key.PrefixLen != 24 {
		t.Fatalf("prefix len = %d, want 24", key.PrefixLen)
	}
	if key.Addr != 0xC0A80000 {
		t.Fatalf("addr = 0x%08x, want 0xC0A80000 (network byte order)", key.Addr)
	}
}
