package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const arphrdEther = 1

var defaultIgnorePatterns = []string{
	"lo",
	"docker0",
	"br-*",
	"veth*",
	"dummy*",
	"tun*",
	"tap*",
	"cilium*",
	"flannel*",
	"cni*",
	"kube*",
	"calico*",
}

// DiscoverTransitInterfaces returns up WireGuard and Ethernet interfaces suitable
// for TC egress attachment, excluding configured and built-in ignore patterns.
func DiscoverTransitInterfaces(ignore []string) ([]string, error) {
	patterns := append(append([]string{}, defaultIgnorePatterns...), ignore...)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if ShouldIgnore(iface.Name, patterns) {
			continue
		}
		if isWireguard(iface.Name) || isEthernet(iface.Name) {
			names = append(names, iface.Name)
		}
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("no transit interfaces found (looking for up wireguard or ethernet interfaces)")
	}

	sort.Strings(names)
	return names, nil
}

func isWireguard(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name, "wireguard"))
	return err == nil
}

func isEthernet(name string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "type"))
	if err != nil {
		return false
	}
	typ, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	return typ == arphrdEther
}
