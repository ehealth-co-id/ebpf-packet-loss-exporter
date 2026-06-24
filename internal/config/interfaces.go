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

// TransitInterfaceNames returns configured interfaces, or auto-discovers
// up WireGuard and Ethernet interfaces when the list is empty.
func (c *Config) TransitInterfaceNames() ([]string, error) {
	if len(c.Interfaces) > 0 {
		return resolveInterfaceNames(c.Interfaces)
	}
	return DiscoverTransitInterfaces()
}

func resolveInterfaceNames(names []string) ([]string, error) {
	seen := make(map[string]struct{}, len(names))
	var out []string

	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup %q: %w", name, err)
		}
		if iface.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("interface %q is not up", name)
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no transit interfaces configured")
	}
	sort.Strings(out)
	return out, nil
}

// DiscoverTransitInterfaces returns up WireGuard and Ethernet interfaces suitable
// for TC egress attachment, excluding built-in ignore patterns.
func DiscoverTransitInterfaces() ([]string, error) {
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
		if ShouldIgnore(iface.Name, defaultIgnorePatterns) {
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
