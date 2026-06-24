package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SourceZone    string              `yaml:"source_zone"`
	Listen        string              `yaml:"listen"`
	PollInterval  time.Duration       `yaml:"poll_interval"`
	InstantWindow time.Duration       `yaml:"instant_window"`
	Interfaces    []string            `yaml:"interfaces,omitempty"`
	Zones         map[string][]string `yaml:"zones"`
	EMAHalfLife   time.Duration       `yaml:"ema_half_life"`

	zoneIDs map[string]uint8
}

type ZoneEntry struct {
	ZoneID uint8
	Prefix net.IPNet
}

type ResolvedZone struct {
	DstZone    string
	ZoneID     uint8
	SourceZone string
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		Listen:        ":9435",
		PollInterval:  1 * time.Second,
		InstantWindow: 10 * time.Second,
		EMAHalfLife:   5 * time.Minute,
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":9435"
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.InstantWindow <= 0 {
		c.InstantWindow = 10 * time.Second
	}
	if c.EMAHalfLife <= 0 {
		c.EMAHalfLife = 5 * time.Minute
	}
}

func (c *Config) Validate() error {
	if c.SourceZone == "" {
		return fmt.Errorf("source_zone is required")
	}
	if len(c.Zones) == 0 {
		return fmt.Errorf("zones map is required")
	}

	if _, ok := c.Zones[c.SourceZone]; !ok {
		return fmt.Errorf("source_zone %q must exist in zones", c.SourceZone)
	}

	remoteZones := 0
	for name, subnets := range c.Zones {
		if len(subnets) == 0 {
			return fmt.Errorf("zone %q: at least one subnet required", name)
		}
		for _, s := range subnets {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return fmt.Errorf("zone %q: invalid subnet %q: %w", name, s, err)
			}
		}
		if name != c.SourceZone {
			remoteZones++
		}
	}
	if remoteZones == 0 {
		return fmt.Errorf("at least one remote zone (other than source_zone) is required")
	}

	if err := c.assignZoneIDs(); err != nil {
		return err
	}

	if c.PollInterval <= 0 {
		return fmt.Errorf("poll_interval must be positive")
	}
	if c.InstantWindow < 0 {
		return fmt.Errorf("instant_window must not be negative")
	}

	return nil
}

func (c *Config) assignZoneIDs() error {
	names := make([]string, 0, len(c.Zones))
	for name := range c.Zones {
		names = append(names, name)
	}
	sort.Strings(names)

	if len(names) > 255 {
		return fmt.Errorf("too many zones: %d (max 255)", len(names))
	}

	c.zoneIDs = make(map[string]uint8, len(names))
	for i, name := range names {
		c.zoneIDs[name] = uint8(i + 1)
	}
	return nil
}

func (c *Config) ZoneID(name string) (uint8, bool) {
	id, ok := c.zoneIDs[name]
	return id, ok
}

// SourceZoneLPMEntries returns LPM trie entries for the configured source zone.
func (c *Config) SourceZoneLPMEntries() ([]ZoneEntry, error) {
	subnets, ok := c.Zones[c.SourceZone]
	if !ok {
		return nil, fmt.Errorf("source_zone %q not found in zones", c.SourceZone)
	}

	zoneID, ok := c.ZoneID(c.SourceZone)
	if !ok {
		return nil, fmt.Errorf("source_zone %q has no assigned id", c.SourceZone)
	}

	var entries []ZoneEntry
	for _, s := range subnets {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("zone %q subnet %q: %w", c.SourceZone, s, err)
		}
		entries = append(entries, ZoneEntry{
			ZoneID: zoneID,
			Prefix: *n,
		})
	}
	return entries, nil
}

// ZoneLPMEntries returns LPM trie entries for remote zones (excludes source zone subnets).
func (c *Config) ZoneLPMEntries() ([]ZoneEntry, error) {
	var entries []ZoneEntry

	for name, subnets := range c.Zones {
		if name == c.SourceZone {
			continue
		}
		zoneID, ok := c.ZoneID(name)
		if !ok {
			return nil, fmt.Errorf("zone %q has no assigned id", name)
		}
		for _, s := range subnets {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("zone %q subnet %q: %w", name, s, err)
			}
			entries = append(entries, ZoneEntry{
				ZoneID: zoneID,
				Prefix: *n,
			})
		}
	}

	return entries, nil
}

// RemoteZones returns one entry per remote zone for metrics and BPF classification.
func (c *Config) RemoteZones() []ResolvedZone {
	names := make([]string, 0, len(c.Zones))
	for name := range c.Zones {
		if name != c.SourceZone {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	zones := make([]ResolvedZone, 0, len(names))
	for _, name := range names {
		id, _ := c.ZoneID(name)
		zones = append(zones, ResolvedZone{
			DstZone:    name,
			ZoneID:     id,
			SourceZone: c.SourceZone,
		})
	}
	return zones
}

func ShouldIgnore(name string, patterns []string) bool {
	for _, pattern := range patterns {
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

func (c *Config) Alpha(dt time.Duration) float64 {
	if c.EMAHalfLife <= 0 {
		return 0.3
	}
	return 1 - expNeg(dt.Seconds()/c.EMAHalfLife.Seconds())
}

// expNeg computes e^(-x) via series for small values; sufficient for EMA alpha.
func expNeg(x float64) float64 {
	if x <= 0 {
		return 1
	}
	return mathExpNeg(x)
}
