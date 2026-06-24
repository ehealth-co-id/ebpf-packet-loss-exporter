package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Exporter struct {
	registry *prometheus.Registry

	percent       *prometheus.GaugeVec
	percentEMA    *prometheus.GaugeVec
	segmentsTotal *prometheus.CounterVec
	retransTotal  *prometheus.CounterVec
	emaTimestamp  *prometheus.GaugeVec

	mu          sync.RWMutex
	lastSeg     map[string]uint64
	lastRetrans map[string]uint64
}

func NewExporter() *Exporter {
	reg := prometheus.NewRegistry()

	e := &Exporter{
		registry:    reg,
		lastSeg:     make(map[string]uint64),
		lastRetrans: make(map[string]uint64),
		percent: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_percent",
			Help: "Instant TCP packet loss percent from the last poll window.",
		}, []string{"name", "source_zone", "path", "dst_zone"}),
		percentEMA: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_percent_ema",
			Help: "EMA-smoothed TCP packet loss percent; primary series for dashboards.",
		}, []string{"name", "source_zone", "path", "dst_zone"}),
		segmentsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_packet_loss_segments_total",
			Help: "Total TCP segments observed by BPF (debug).",
		}, []string{"name", "source_zone", "path", "dst_zone"}),
		retransTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_packet_loss_retrans_total",
			Help: "Total TCP retransmits observed by BPF (debug).",
		}, []string{"name", "source_zone", "path", "dst_zone"}),
		emaTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_ema_last_update_timestamp",
			Help: "Unix timestamp of the last EMA update per target.",
		}, []string{"name", "source_zone", "path", "dst_zone"}),
	}

	reg.MustRegister(
		e.percent,
		e.percentEMA,
		e.segmentsTotal,
		e.retransTotal,
		e.emaTimestamp,
	)

	return e
}

func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

func (e *Exporter) Publish(states []TargetState) {
	e.mu.Lock()
	defer e.mu.Unlock()

	seen := make(map[string]struct{}, len(states))
	for _, st := range states {
		labels := prometheus.Labels{
			"name":        st.Target.Name,
			"source_zone": st.Target.SourceZone,
			"path":        st.Target.Path,
			"dst_zone":    st.Target.DstZone,
		}

		e.percent.With(labels).Set(st.InstantPercent)
		e.percentEMA.With(labels).Set(st.EMAPercent)

		if !st.LastUpdate.IsZero() {
			e.emaTimestamp.With(labels).Set(float64(st.LastUpdate.Unix()))
		}

		prevSeg := e.lastSeg[st.Target.Name]
		prevRet := e.lastRetrans[st.Target.Name]
		curSeg := st.LastSegments
		curRet := st.LastRetrans

		if curSeg >= prevSeg {
			e.segmentsTotal.With(labels).Add(float64(curSeg - prevSeg))
		} else {
			e.segmentsTotal.With(labels).Add(float64(curSeg))
		}
		if curRet >= prevRet {
			e.retransTotal.With(labels).Add(float64(curRet - prevRet))
		} else {
			e.retransTotal.With(labels).Add(float64(curRet))
		}

		e.lastSeg[st.Target.Name] = curSeg
		e.lastRetrans[st.Target.Name] = curRet
		seen[st.Target.Name] = struct{}{}
	}

	// Reset gauges for removed targets (unlikely at runtime).
	e.percent.Reset()
	e.percentEMA.Reset()
	e.emaTimestamp.Reset()
	for _, st := range states {
		labels := prometheus.Labels{
			"name":        st.Target.Name,
			"source_zone": st.Target.SourceZone,
			"path":        st.Target.Path,
			"dst_zone":    st.Target.DstZone,
		}
		e.percent.With(labels).Set(st.InstantPercent)
		e.percentEMA.With(labels).Set(st.EMAPercent)
		if !st.LastUpdate.IsZero() {
			e.emaTimestamp.With(labels).Set(float64(st.LastUpdate.Unix()))
		}
	}
}
