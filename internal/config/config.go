package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SourceZone   string        `yaml:"source_zone"`
	Listen       string        `yaml:"listen"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Interfaces   Interfaces    `yaml:"interfaces"`
	Zones        map[string]Zone `yaml:"zones"`
	Targets      []Target      `yaml:"targets"`
	EMA          EMAConfig     `yaml:"ema"`
}

type Interfaces struct {
	Wireguard []string `yaml:"wireguard"`
	L2        []string `yaml:"l2"`
	Ignore    []string `yaml:"ignore"`
}

type Zone struct {
	ID      uint8    `yaml:"id"`
	Subnets []string `yaml:"subnets"`
}

type Target struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host,omitempty"`
	DstZone string `yaml:"dst_zone"`
	Path    string `yaml:"path"`
}

type EMAConfig struct {
	HalfLife time.Duration `yaml:"half_life"`
	Alpha    *float64      `yaml:"alpha,omitempty"`
}

type ZoneEntry struct {
	ZoneID uint8
	Prefix net.IPNet
}

type ResolvedTarget struct {
	Name       string
	DstZone    string
	Path       string
	ZoneID     uint8
	IfIndex    int
	SourceZone string
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		Listen:       ":9435",
		PollInterval: 15 * time.Second,
		EMA: EMAConfig{
			HalfLife: 5 * time.Minute,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.SourceZone == "" {
		return fmt.Errorf("source_zone is required")
	}
	if len(c.Interfaces.Wireguard) == 0 && len(c.Interfaces.L2) == 0 {
		return fmt.Errorf("at least one wireguard or l2 interface is required")
	}
	if len(c.Zones) == 0 {
		return fmt.Errorf("zones map is required")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}

	if _, ok := c.Zones[c.SourceZone]; !ok {
		return fmt.Errorf("source_zone %q must exist in zones", c.SourceZone)
	}

	for name, zone := range c.Zones {
		if zone.ID == 0 {
			return fmt.Errorf("zone %q: id must be non-zero", name)
		}
		if len(zone.Subnets) == 0 {
			return fmt.Errorf("zone %q: subnets required", name)
		}
		for _, s := range zone.Subnets {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return fmt.Errorf("zone %q: invalid subnet %q: %w", name, s, err)
			}
		}
	}

	ids := map[uint8]string{}
	for name, zone := range c.Zones {
		if other, exists := ids[zone.ID]; exists {
			return fmt.Errorf("duplicate zone id %d for zones %q and %q", zone.ID, other, name)
		}
		ids[zone.ID] = name
	}

	for i, t := range c.Targets {
		if t.Name == "" {
			return fmt.Errorf("target[%d]: name is required", i)
		}
		if t.DstZone == "" {
			return fmt.Errorf("target %q: dst_zone is required", t.Name)
		}
		if t.Path != "wireguard" && t.Path != "l2" {
			return fmt.Errorf("target %q: path must be wireguard or l2", t.Name)
		}
		if _, ok := c.Zones[t.DstZone]; !ok {
			return fmt.Errorf("target %q: unknown dst_zone %q", t.Name, t.DstZone)
		}
		if t.DstZone == c.SourceZone {
			return fmt.Errorf("target %q: dst_zone cannot equal source_zone", t.Name)
		}
	}

	if c.PollInterval <= 0 {
		return fmt.Errorf("poll_interval must be positive")
	}
	if c.EMA.HalfLife <= 0 && c.EMA.Alpha == nil {
		return fmt.Errorf("ema.half_life must be positive when alpha is not set")
	}
	if c.EMA.Alpha != nil && (*c.EMA.Alpha <= 0 || *c.EMA.Alpha > 1) {
		return fmt.Errorf("ema.alpha must be in (0, 1]")
	}

	return nil
}

// SourceZoneLPMEntries returns LPM trie entries for the configured source zone.
func (c *Config) SourceZoneLPMEntries() ([]ZoneEntry, error) {
	zone, ok := c.Zones[c.SourceZone]
	if !ok {
		return nil, fmt.Errorf("source_zone %q not found in zones", c.SourceZone)
	}

	var entries []ZoneEntry
	for _, s := range zone.Subnets {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("zone %q subnet %q: %w", c.SourceZone, s, err)
		}
		entries = append(entries, ZoneEntry{
			ZoneID: zone.ID,
			Prefix: *n,
		})
	}
	return entries, nil
}

// ZoneLPMEntries returns LPM trie entries for remote zones (excludes source zone subnets).
func (c *Config) ZoneLPMEntries() ([]ZoneEntry, error) {
	var entries []ZoneEntry

	for name, zone := range c.Zones {
		if name == c.SourceZone {
			continue
		}
		for _, s := range zone.Subnets {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("zone %q subnet %q: %w", name, s, err)
			}
			entries = append(entries, ZoneEntry{
				ZoneID: zone.ID,
				Prefix: *n,
			})
		}
	}

	return entries, nil
}

func (c *Config) InterfaceNames() []string {
	names := append([]string{}, c.Interfaces.Wireguard...)
	names = append(names, c.Interfaces.L2...)
	return names
}

func (c *Config) PathForInterface(name string) (string, bool) {
	for _, n := range c.Interfaces.Wireguard {
		if n == name {
			return "wireguard", true
		}
	}
	for _, n := range c.Interfaces.L2 {
		if n == name {
			return "l2", true
		}
	}
	return "", false
}

func (c *Config) ShouldIgnore(name string) bool {
	for _, pattern := range c.Interfaces.Ignore {
		if pattern == name {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

func (c *Config) ResolveTargets(ifIndexByName map[string]int) ([]ResolvedTarget, error) {
	var resolved []ResolvedTarget

	for _, t := range c.Targets {
		var ifNames []string
		switch t.Path {
		case "wireguard":
			ifNames = c.Interfaces.Wireguard
		case "l2":
			ifNames = c.Interfaces.L2
		}
		if len(ifNames) == 0 {
			return nil, fmt.Errorf("target %q: no interfaces configured for path %q", t.Name, t.Path)
		}

		zone, ok := c.Zones[t.DstZone]
		if !ok {
			return nil, fmt.Errorf("target %q: unknown zone %q", t.Name, t.DstZone)
		}

		// Use first interface for the path; counters aggregate per (ifindex, zone_id).
		ifIdx, ok := ifIndexByName[ifNames[0]]
		if !ok {
			return nil, fmt.Errorf("target %q: interface %q not found", t.Name, ifNames[0])
		}

		resolved = append(resolved, ResolvedTarget{
			Name:       t.Name,
			DstZone:    t.DstZone,
			Path:       t.Path,
			ZoneID:     zone.ID,
			IfIndex:    ifIdx,
			SourceZone: c.SourceZone,
		})
	}

	return resolved, nil
}

func (c *Config) Alpha(dt time.Duration) float64 {
	if c.EMA.Alpha != nil {
		return *c.EMA.Alpha
	}
	if c.EMA.HalfLife <= 0 {
		return 0.3
	}
	return 1 - expNeg(dt.Seconds()/c.EMA.HalfLife.Seconds())
}

// expNeg computes e^(-x) via series for small values; sufficient for EMA alpha.
func expNeg(x float64) float64 {
	if x <= 0 {
		return 1
	}
	// Use math.Exp would be cleaner but keep import minimal - actually use math
	return mathExpNeg(x)
}
