package tcattach

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/bpf"
)

type Attachment struct {
	link link.Link
}

func AttachEgress(ifaceName string, prog *ebpf.Program, coll *bpf.Collection) (*Attachment, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx egress on %q: %w", ifaceName, err)
	}

	coll.AddLink(l)
	return &Attachment{link: l}, nil
}

func (a *Attachment) Close() error {
	if a == nil || a.link == nil {
		return nil
	}
	return a.link.Close()
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
