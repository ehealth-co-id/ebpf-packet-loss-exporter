package bpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

type zoneLpmKey struct {
	PrefixLen uint32
	Addr      uint32
}

// StatsEvent mirrors struct stats_event in bpf/packet_loss.bpf.c.
type StatsEvent struct {
	IfIndex   uint32
	DstZoneID uint8
	IsRetrans uint8
	Pad       uint16
}

type Collection struct {
	objs  *PacketLossObjects
	links []linkCloser
}

type linkCloser interface {
	Close() error
}

type DebugCounters struct {
	TCPPackets uint64
	TCPZoned   uint64
}

func Load(dstEntries, srcEntries []config.ZoneEntry) (*Collection, error) {
	objs := &PacketLossObjects{}
	if err := LoadPacketLossObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	for _, e := range dstEntries {
		key := lpmKeyFromNet(e.Prefix)
		zoneID := e.ZoneID
		if err := objs.ZoneLpm.Put(key, zoneID); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("populate zone_lpm %s: %w", e.Prefix.String(), err)
		}
	}

	for _, e := range srcEntries {
		key := lpmKeyFromNet(e.Prefix)
		zoneID := e.ZoneID
		if err := objs.SrcZoneLpm.Put(key, zoneID); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("populate src_zone_lpm %s: %w", e.Prefix.String(), err)
		}
	}

	return &Collection{objs: objs}, nil
}

func (c *Collection) Program() *ebpf.Program {
	return c.objs.PathEgress
}

func (c *Collection) AddLink(l linkCloser) {
	c.links = append(c.links, l)
}

func (c *Collection) NewRingbufReader() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(c.objs.StatsRb)
}

func (c *Collection) ReadDebugCounters() (DebugCounters, error) {
	var out DebugCounters
	var err error
	out.TCPPackets, err = sumPerCPUArray(c.objs.DebugTcpPayload)
	if err != nil {
		return out, err
	}
	out.TCPZoned, err = sumPerCPUArray(c.objs.DebugTcpZoned)
	return out, err
}

func (c *Collection) Close() error {
	var first error
	for _, l := range c.links {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := c.objs.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

func lpmKeyFromNet(n net.IPNet) zoneLpmKey {
	ip := n.IP.To4()
	if ip == nil {
		return zoneLpmKey{}
	}
	ones, _ := n.Mask.Size()
	return zoneLpmKey{
		PrefixLen: uint32(ones),
		Addr:      binary.NativeEndian.Uint32(ip),
	}
}

func sumPerCPU(m *ebpf.Map, key interface{}) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

func sumPerCPUArray(m *ebpf.Map) (uint64, error) {
	var key uint32
	return sumPerCPU(m, key)
}
