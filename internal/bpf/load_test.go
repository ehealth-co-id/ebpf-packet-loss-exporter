package bpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"
)

func TestLpmKeyFromNetWireFormat(t *testing.T) {
	_, n, err := net.ParseCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	key := lpmKeyFromNet(*n)
	if key.PrefixLen != 24 {
		t.Fatalf("prefix len = %d, want 24", key.PrefixLen)
	}

	want := n.IP.To4()
	got := (*[4]byte)(unsafe.Pointer(&key.Addr))
	if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
		t.Fatalf("addr bytes = %v, want wire-format %v (uint32=0x%08x)", *got, want, key.Addr)
	}

	// Matches v0.0.7 encoding on little-endian hosts.
	if binary.NativeEndian.Uint32(want) != key.Addr {
		t.Fatalf("addr uint32 = 0x%08x, want native-endian 0x%08x", key.Addr, binary.NativeEndian.Uint32(want))
	}
}
