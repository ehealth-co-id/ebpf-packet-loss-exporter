package metrics

import (
	"math"
	"sync"
	"time"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

type CounterSnapshot struct {
	Segments uint64
	Retrans  uint64
}

type sample struct {
	seg uint64
	ret uint64
}

type ZoneState struct {
	SourceZone     string
	DstZone        string
	InstantPercent float64
	EMAPercent     float64
	LastUpdate     time.Time
	LastPoll       time.Time
	window         []sample
	windowCap      int
	windowPos      int
	windowLen      int
	sumSeg         uint64
	sumRet         uint64
}

type EMAStore struct {
	mu    sync.RWMutex
	cfg   *config.Config
	zones map[string]*ZoneState
}

func instantWindowCap(cfg *config.Config) int {
	n := int(cfg.InstantWindow / cfg.PollInterval)
	if n < 1 {
		n = 1
	}
	return n
}

func NewEMAStore(cfg *config.Config, zones []config.ResolvedZone) *EMAStore {
	cap := instantWindowCap(cfg)
	zoneStates := make(map[string]*ZoneState, len(zones))

	for _, z := range zones {
		zoneStates[z.DstZone] = &ZoneState{
			SourceZone: z.SourceZone,
			DstZone:    z.DstZone,
			window:     make([]sample, cap),
			windowCap:  cap,
		}
	}

	return &EMAStore{
		cfg:   cfg,
		zones: zoneStates,
	}
}

func (s *EMAStore) Update(now time.Time, counters map[string]CounterSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for dstZone, state := range s.zones {
		delta := counters[dstZone]

		dt := s.cfg.PollInterval
		if !state.LastPoll.IsZero() {
			dt = now.Sub(state.LastPoll)
		}

		if state.windowLen == state.windowCap {
			old := state.window[state.windowPos]
			state.sumSeg -= old.seg
			state.sumRet -= old.ret
		} else {
			state.windowLen++
		}
		state.window[state.windowPos] = sample{seg: delta.Segments, ret: delta.Retrans}
		state.sumSeg += delta.Segments
		state.sumRet += delta.Retrans
		state.windowPos = (state.windowPos + 1) % state.windowCap

		if state.sumSeg > 0 {
			instant := 100.0 * float64(state.sumRet) / float64(state.sumSeg)
			state.InstantPercent = instant

			alpha := s.cfg.Alpha(dt)
			if state.LastUpdate.IsZero() {
				state.EMAPercent = instant
			} else {
				state.EMAPercent = alpha*instant + (1-alpha)*state.EMAPercent
			}
			state.LastUpdate = now
		}
		// When sumSeg == 0: hold EMA and instant values unchanged.

		state.LastPoll = now
	}
}

func (s *EMAStore) Snapshot() []ZoneState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ZoneState, 0, len(s.zones))
	for _, st := range s.zones {
		cp := *st
		out = append(out, cp)
	}
	return out
}

// AlphaFromHalfLife is exported for tests.
func AlphaFromHalfLife(dt, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		return 0.3
	}
	return 1 - math.Exp(-dt.Seconds()/halfLife.Seconds())
}
