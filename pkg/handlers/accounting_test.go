package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

// accessRecords serves one request through h, wrapped in the log middleware, and returns the access records.
func accessRecords(t *testing.T, h http.Handler, target string) []map[string]any {
	t.Helper()
	var access syncBuffer
	p := httptest.NewServer(log.Middleware(slog.New(slog.NewJSONHandler(&access, nil)), slog.New(slog.DiscardHandler))(h))
	defer p.Close()
	tr := testTransport(p.URL)
	rq, _ := http.NewRequest(http.MethodGet, target, nil)
	if rs, err := tr.RoundTrip(rq); err == nil {
		_, _ = io.Copy(io.Discard, rs.Body)
		_ = rs.Body.Close()
	}
	tr.CloseIdleConnections()
	require.Eventually(t, func() bool { return access.Len() > 0 }, 5*time.Second, 10*time.Millisecond)

	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(access.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		out = append(out, m)
	}
	return out
}

func TestAccessAccounting(t *testing.T) {
	t.Run("plain HTTP", func(t *testing.T) {
		recs := accessRecords(t, &handlers.HTTPHandler{}, testServer.URL+"/bytes/100")
		require.Len(t, recs, 1)
		require.EqualValues(t, 200, recs[0]["status"])
		require.EqualValues(t, 100, recs[0]["content-length"])
	})
	t.Run("tunnel", func(t *testing.T) {
		recs := accessRecords(t, &handlers.Tunnel{}, testTLSServer.URL+"/bytes/100")
		require.Len(t, recs, 1)
		require.EqualValues(t, 200, recs[0]["status"])
		require.Greater(t, recs[0]["content-length"], float64(100))
	})
	t.Run("MITM", func(t *testing.T) {
		recs := accessRecords(t, trustingMITM(), testTLSServer.URL+"/bytes/100")
		require.Len(t, recs, 1)
		require.EqualValues(t, 200, recs[0]["status"])
		require.Greater(t, recs[0]["content-length"], float64(100))
	})
	t.Run("refused CONNECT", func(t *testing.T) {
		recs := accessRecords(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "no", http.StatusForbidden)
		}), testTLSServer.URL+"/")
		require.Len(t, recs, 1)
		require.EqualValues(t, 403, recs[0]["status"])
	})
}

// syncBuffer is a bytes.Buffer safe for a writer and a reader on different goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
