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

func Load(entries []config.ZoneEntry) (*Collection, error) {
	objs := &PacketLossObjects{}
	if err := LoadPacketLossObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	for _, e := range entries {
		key := lpmKeyFromNet(e.Prefix)
		zoneID := e.ZoneID
		if err := objs.ZoneLpm.Put(key, zoneID); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("populate zone_lpm: %w", err)
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

	segVals, err := c.objs.TcpSegments.LookupBytes(key)
	if err != nil {
		return 0, 0, nil
	}
	retVals, err := c.objs.TcpRetrans.LookupBytes(key)
	if err != nil {
		return sumUint64Slice(segVals), 0, nil
	}

	return sumUint64Slice(segVals), sumUint64Slice(retVals), nil
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
		Addr:      binary.BigEndian.Uint32(ip),
	}
}

func sumUint64Slice(vals []byte) uint64 {
	if len(vals) == 0 {
		return 0
	}
	const u64 = 8
	var total uint64
	for i := 0; i+u64 <= len(vals); i += u64 {
		total += binary.LittleEndian.Uint64(vals[i : i+u64])
	}
	return total
}

// ReadAllCounterKeys aggregates every BPF counter entry for debugging.
func (c *Collection) ReadAllCounterKeys() (map[counterKey]uint64, error) {
	out := make(map[counterKey]uint64)
	iter := c.objs.TcpSegments.Iterate()
	var key counterKey
	var vals []byte
	for iter.Next(&key, &vals) {
		out[key] = sumUint64Slice(vals)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
