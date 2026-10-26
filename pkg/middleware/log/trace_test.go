package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

func TestTraceHandler(t *testing.T) {
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	traced := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))

	record := func(ctx context.Context) map[string]any {
		t.Helper()
		var buf bytes.Buffer
		l := slog.New(log.TraceHandler(slog.NewJSONHandler(&buf, nil))).With("k", "v")
		l.InfoContext(ctx, "hello")
		var m map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &m))
		return m
	}

	t.Run("a context with a span", func(t *testing.T) {
		m := record(traced)
		require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", m["trace_id"])
		require.Equal(t, "00f067aa0ba902b7", m["span_id"])
		require.Equal(t, "v", m["k"])
	})
	t.Run("a context without one", func(t *testing.T) {
		m := record(context.Background())
		require.NotContains(t, m, "trace_id")
		require.NotContains(t, m, "span_id")
	})
}
