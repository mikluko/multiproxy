package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func TestExportErrorLevel(t *testing.T) {
	require.Equal(t, slog.LevelDebug, exportErrorLevel())
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "http://collector.test:4318")
			require.Equal(t, slog.LevelWarn, exportErrorLevel())
		})
	}
}

func TestSetupTelemetry_disabled(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", "TRUE")
	before := otel.GetTracerProvider()

	var stderr bytes.Buffer
	_, server, shutdown, err := setupTelemetry(context.Background(), io.Discard, &stderr)
	require.NoError(t, err)
	server.Info("hello")
	require.NoError(t, shutdown(context.Background()))

	require.Equal(t, before, otel.GetTracerProvider())
	require.Contains(t, stderr.String(), `"msg":"hello"`)
}

func TestSetupTelemetry_exports(t *testing.T) {
	var (
		mu       sync.Mutex
		received = map[string]int{}
	)
	collector := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		mu.Lock()
		received[rq.URL.Path]++
		mu.Unlock()
		_, _ = io.Copy(io.Discard, rq.Body)
		rw.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()

	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Cleanup(func() {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})

	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, rq *http.Request) {
		seen <- rq.Header.Get("Traceparent")
	}))
	defer upstream.Close()

	var stdout bytes.Buffer
	access, server, shutdown, err := setupTelemetry(context.Background(), &stdout, io.Discard)
	require.NoError(t, err)
	cfg, err := parseFlags(nil, io.Discard)
	require.NoError(t, err)
	ca, err := loadCA(cfg)
	require.NoError(t, err)
	h, err := newHandler(cfg, ca, access, server)
	require.NoError(t, err)
	p := httptest.NewServer(h)
	defer p.Close()

	const clientTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	rq, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	rq.Header.Set("Traceparent", "00-"+clientTrace+"-00f067aa0ba902b7-01")
	pu, err := url.Parse(p.URL)
	require.NoError(t, err)
	rs, err := client(pu).Do(rq)
	require.NoError(t, err)
	_ = rs.Body.Close()

	traceparent := <-seen
	require.Contains(t, traceparent, clientTrace)
	require.NotContains(t, traceparent, "00f067aa0ba902b7")

	require.NoError(t, shutdown(context.Background()))
	require.Contains(t, stdout.String(), `"trace_id":"`+clientTrace+`"`)

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/v1/traces", "/v1/metrics", "/v1/logs"} {
		require.Positive(t, received[path], "%s in %v", path, received)
	}
}
