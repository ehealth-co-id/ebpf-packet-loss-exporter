package bpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

type zoneLpmKey struct {
	PrefixLen uint32
	Addr      uint32
}

type counterKey struct {
	IfIndex   uint32
	DstZoneID uint8
	Pad       [3]uint8
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

func (c *Collection) ReadCounters(target config.ResolvedTarget) (segments, retrans uint64, err error) {
	key := counterKey{
		IfIndex:   uint32(target.IfIndex),
		DstZoneID: target.ZoneID,
	}

	segments, err = sumPerCPU(c.objs.TcpSegments, key)
	if err != nil {
		return 0, 0, nil
	}
	retrans, err = sumPerCPU(c.objs.TcpRetrans, key)
	if err != nil {
		return segments, 0, nil
	}
	return segments, retrans, nil
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

// ReadAllCounterKeys aggregates every BPF counter entry for debugging.
func (c *Collection) ReadAllCounterKeys() (map[counterKey]uint64, error) {
	out := make(map[counterKey]uint64)
	iter := c.objs.TcpSegments.Iterate()
	var key counterKey
	var vals []uint64
	for iter.Next(&key, &vals) {
		var total uint64
		for _, v := range vals {
			total += v
		}
		out[key] = total
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
