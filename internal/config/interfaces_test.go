package config

import (
	"testing"
)

func TestAutoZoneIDs(t *testing.T) {
	cfg := &Config{
		SourceZone:   "e",
		PollInterval: 1,
		EMAHalfLife:  1,
		Zones: map[string][]string{
			"f": {"192.168.5.0/24"},
			"c": {"192.168.0.0/24"},
			"e": {"192.168.3.0/24"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	want := map[string]uint8{"c": 1, "e": 2, "f": 3}
	for name, wantID := range want {
		got, ok := cfg.ZoneID(name)
		if !ok {
			t.Fatalf("zone %q has no id", name)
		}
		if got != wantID {
			t.Fatalf("zone %q id = %d, want %d", name, got, wantID)
		}
	}
}

func TestTransitInterfaceNamesExplicit(t *testing.T) {
	cfg := &Config{
		Interfaces: []string{"nonexistent0"},
	}
	_, err := cfg.TransitInterfaceNames()
	if err == nil {
		t.Fatal("expected error for unknown interface")
	}
}
