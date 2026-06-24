package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Exporter struct {
	registry *prometheus.Registry

	percent      *prometheus.GaugeVec
	percentEMA   *prometheus.GaugeVec
	emaTimestamp *prometheus.GaugeVec
}

func NewExporter() *Exporter {
	reg := prometheus.NewRegistry()

	e := &Exporter{
		registry: reg,
		percent: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_percent",
			Help: "Instant TCP packet loss percent from the last poll window.",
		}, []string{"source_zone", "dst_zone"}),
		percentEMA: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_percent_ema",
			Help: "EMA-smoothed TCP packet loss percent; primary series for dashboards.",
		}, []string{"source_zone", "dst_zone"}),
		emaTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_packet_loss_ema_last_update_timestamp",
			Help: "Unix timestamp of the last EMA update per zone pair.",
		}, []string{"source_zone", "dst_zone"}),
	}

	reg.MustRegister(
		e.percent,
		e.percentEMA,
		e.emaTimestamp,
	)

	return e
}

func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

func (e *Exporter) Publish(states []ZoneState) {
	e.percent.Reset()
	e.percentEMA.Reset()
	e.emaTimestamp.Reset()

	for _, st := range states {
		labels := prometheus.Labels{
			"source_zone": st.SourceZone,
			"dst_zone":    st.DstZone,
		}

		e.percent.With(labels).Set(st.InstantPercent)
		e.percentEMA.With(labels).Set(st.EMAPercent)

		if !st.LastUpdate.IsZero() {
			e.emaTimestamp.With(labels).Set(float64(st.LastUpdate.Unix()))
		}
	}
}
