package surrealzone

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	queriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "surrealzone",
		Name:      "queries_total",
		Help:      "Total DNS queries served from SurrealDB.",
	})

	errorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "surrealzone",
		Name:      "errors_total",
		Help:      "Total SurrealDB query errors.",
	})
)
