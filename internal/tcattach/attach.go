package tcattach

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const filterHandleBase = 0x1600

type Attachment struct {
	link     link.Link
	clsact   *clsactFilter
	ifaceIdx int
}

func AttachEgress(ifaceName string, prog *ebpf.Program, coll *bpf.Collection) (*Attachment, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	a, err := attachTCXEgress(iface, prog, coll)
	if err == nil {
		return a, nil
	}
	if !isTCXUnsupported(err) {
		return nil, fmt.Errorf("attach tcx egress on %q: %w", ifaceName, err)
	}

	cls, err := attachClsActEgress(ifaceName, iface.Index, prog)
	if err != nil {
		return nil, fmt.Errorf("attach clsact egress on %q: %w", ifaceName, err)
	}
	log.Printf("tcx unavailable; attached clsact egress on %q", ifaceName)
	coll.AddLink(cls)
	return &Attachment{clsact: cls, ifaceIdx: iface.Index}, nil
}

func attachTCXEgress(iface *net.Interface, prog *ebpf.Program, coll *bpf.Collection) (*Attachment, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, err
	}
	coll.AddLink(l)
	return &Attachment{link: l, ifaceIdx: iface.Index}, nil
}

func isTCXUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tcx not supported") ||
		strings.Contains(msg, "not supported") && strings.Contains(msg, "tcx")
}

type clsactFilter struct {
	ifaceName string
	ifaceIdx  int
	handle    uint32
	parent    uint32
}

func (c *clsactFilter) Close() error {
	if c == nil || c.handle == 0 {
		return nil
	}

	link, err := netlink.LinkByIndex(c.ifaceIdx)
	if err != nil {
		return fmt.Errorf("lookup interface index %d: %w", c.ifaceIdx, err)
	}

	filters, err := netlink.FilterList(link, c.parent)
	if err != nil {
		return fmt.Errorf("list filters: %w", err)
	}

	for _, filter := range filters {
		if filter.Attrs().Handle == c.handle {
			if err := netlink.FilterDel(filter); err != nil {
				return fmt.Errorf("delete filter: %w", err)
			}
			c.handle = 0
			return nil
		}
	}
	return fmt.Errorf("filter handle %#x not found on %q", c.handle, c.ifaceName)
}

func attachClsActEgress(ifaceName string, ifaceIdx int, prog *ebpf.Program) (*clsactFilter, error) {
	nl, err := netlink.LinkByIndex(ifaceIdx)
	if err != nil {
		return nil, fmt.Errorf("netlink lookup: %w", err)
	}

	if err := ensureClsAct(nl); err != nil {
		return nil, err
	}

	parent := uint32(netlink.HANDLE_MIN_EGRESS)
	handle, err := nextFilterHandle(nl, parent)
	if err != nil {
		return nil, err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIdx,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "path_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("add bpf filter: %w", err)
	}

	return &clsactFilter{
		ifaceName: ifaceName,
		ifaceIdx:  ifaceIdx,
		handle:    handle,
		parent:    parent,
	}, nil
}

func ensureClsAct(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return verifyClsAct(link)
		}
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}

func verifyClsAct(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		attrs := q.Attrs()
		if attrs.Parent == netlink.HANDLE_CLSACT {
			if q.Type() == "clsact" {
				return nil
			}
			return fmt.Errorf("interface already has non-clsact qdisc on clsact parent: %s", q.Type())
		}
	}
	return nil
}

func nextFilterHandle(link netlink.Link, parent uint32) (uint32, error) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return 0, err
	}

	used := make(map[uint32]struct{}, len(filters))
	for _, f := range filters {
		used[f.Attrs().Handle] = struct{}{}
	}

	for handle := uint32(filterHandleBase); handle < 0xffff; handle++ {
		if _, ok := used[handle]; !ok {
			return handle, nil
		}
	}
	return 0, errors.New("no free tc filter handles")
}

func (a *Attachment) Close() error {
	if a == nil {
		return nil
	}
	if a.link != nil {
		return a.link.Close()
	}
	if a.clsact != nil {
		return a.clsact.Close()
	}
	return nil
}

func AttachAll(names []string, prog *ebpf.Program, coll *bpf.Collection) ([]*Attachment, error) {
	var attachments []*Attachment
	for _, name := range names {
		a, err := AttachEgress(name, prog, coll)
		if err != nil {
			for _, existing := range attachments {
				_ = existing.Close()
			}
			return nil, err
		}
		attachments = append(attachments, a)
	}
	return attachments, nil
}
