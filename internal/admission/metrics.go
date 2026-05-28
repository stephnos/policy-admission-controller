package admission

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "admission_requests_total",
		Help: "Total admission requests handled by result.",
	}, []string{"result"})

	latencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "admission_latency_seconds",
		Help:    "Admission request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	policyEvalErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "policy_eval_errors_total",
		Help: "Total policy evaluation or decode errors.",
	})
)
