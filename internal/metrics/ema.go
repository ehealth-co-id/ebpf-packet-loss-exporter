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

type TargetState struct {
	Target         config.ResolvedTarget
	LastSegments   uint64
	LastRetrans    uint64
	InstantPercent float64
	EMAPercent     float64
	LastUpdate     time.Time
	LastPoll       time.Time
}

type EMAStore struct {
	mu     sync.RWMutex
	cfg    *config.Config
	states map[string]*TargetState
}

func NewEMAStore(cfg *config.Config, targets []config.ResolvedTarget) *EMAStore {
	states := make(map[string]*TargetState, len(targets))
	for _, t := range targets {
		states[t.Name] = &TargetState{Target: t}
	}
	return &EMAStore{
		cfg:    cfg,
		states: states,
	}
}

func (s *EMAStore) Update(now time.Time, counters map[string]CounterSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, state := range s.states {
		snap, ok := counters[name]
		if !ok {
			continue
		}

		deltaSeg := snap.Segments - state.LastSegments
		deltaRet := snap.Retrans - state.LastRetrans

		// Handle counter reset (e.g. BPF reload).
		if snap.Segments < state.LastSegments {
			deltaSeg = snap.Segments
		}
		if snap.Retrans < state.LastRetrans {
			deltaRet = snap.Retrans
		}

		dt := s.cfg.PollInterval
		if !state.LastPoll.IsZero() {
			dt = now.Sub(state.LastPoll)
		}

		if deltaSeg > 0 {
			instant := 100.0 * float64(deltaRet) / float64(deltaSeg)
			state.InstantPercent = instant

			alpha := s.cfg.Alpha(dt)
			if state.LastUpdate.IsZero() {
				state.EMAPercent = instant
			} else {
				state.EMAPercent = alpha*instant + (1-alpha)*state.EMAPercent
			}
			state.LastUpdate = now
		}
		// When deltaSeg == 0: hold EMA and instant values unchanged.

		state.LastSegments = snap.Segments
		state.LastRetrans = snap.Retrans
		state.LastPoll = now
	}
}

func (s *EMAStore) Snapshot() []TargetState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]TargetState, 0, len(s.states))
	for _, st := range s.states {
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
