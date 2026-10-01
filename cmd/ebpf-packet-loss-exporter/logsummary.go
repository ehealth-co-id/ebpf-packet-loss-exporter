package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

// summaryHeartbeatTicks is how often the tick summary is emitted even when
// nothing changed: at the default 1s poll that is a 30s heartbeat.
const summaryHeartbeatTicks = 30

// zoneTick is one zone's observation for one tick. Loss/EMA are the
// instant-window and smoothed percents the exporter publishes.
type zoneTick struct {
	Zone     string
	Segments uint64
	Retrans  uint64
	Loss     float64
	EMA      float64
}

// tickCounters is everything the poll loop observed in one tick. It is
// rendered as a single summary line (see the logging contract in main.go), so
// the fields here ARE the log format: adding a counter means adding it here
// and in formatTickSummary, which TestFormatTickSummary pins down.
type tickCounters struct {
	Tick    uint64
	Zones   []zoneTick
	TCP     uint64 // new TCP payload packets seen by bpf this tick
	Zoned   uint64 // of which matched a zone
	Unknown uint64 // cumulative ringbuf events dropped for unknown zone_id
}

// formatTickSummary renders the summary as (body, volume). The body is the
// slowly-changing part (loss/EMA at 0.1% resolution, warn flags) and is what
// change detection compares; volume is the per-tick seg/retrans counts, which
// change every tick and so ride along without triggering a line by themselves.
func formatTickSummary(c tickCounters) (body, volume string) {
	zs := append([]zoneTick(nil), c.Zones...)
	sort.Slice(zs, func(i, j int) bool { return zs[i].Zone < zs[j].Zone })

	var b, v []string
	for _, z := range zs {
		if z.Segments == 0 && z.Loss == 0 && z.EMA == 0 {
			b = append(b, z.Zone+"=idle")
		} else {
			b = append(b, fmt.Sprintf("%s=loss%.1f%%/ema%.1f%%", z.Zone, z.Loss, z.EMA))
		}
		v = append(v, fmt.Sprintf("%s:%d/%d", z.Zone, z.Segments, z.Retrans))
	}
	body = strings.Join(b, " ")
	switch {
	case c.TCP == 0 && c.Zoned == 0:
		body += " warn=no-tcp"
	case c.TCP > 0 && c.Zoned == 0:
		body += " warn=unzoned(check source_zone/subnets)"
	}
	if c.Unknown > 0 {
		body += fmt.Sprintf(" unknown_zone_drops=%d", c.Unknown)
	}
	return body, strings.Join(v, " ")
}

// emitTickSummary logs the summary when its body changed, or when the
// heartbeat interval elapsed. Per-tick volume is appended to whatever line is
// emitted so every line carries current load.
func emitTickSummary(prevBody *string, lastEmitTick *uint64, c tickCounters) {
	body, volume := formatTickSummary(c)
	if body == *prevBody && c.Tick-*lastEmitTick < summaryHeartbeatTicks {
		return
	}
	*prevBody = body
	*lastEmitTick = c.Tick
	log.Printf("tick %d: %s seg/ret=%s", c.Tick, body, volume)
}
