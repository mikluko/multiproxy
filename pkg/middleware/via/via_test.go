package via_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/middleware/via"
)

func TestViaMiddleware(t *testing.T) {
	ident := "some-hostname.local"
	s := httptest.NewServer(via.Middleware(ident)(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		require.Equal(t, "1.1 example, 1.1 "+ident, r.Header.Get("via"))
		rw.WriteHeader(http.StatusNoContent)
	})))
	defer s.Close()

	rq, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	rq.Header.Add("via", "1.1 example")

	_, err := http.DefaultTransport.RoundTrip(rq)
	require.NoError(t, err)
}

func TestViaHostname(t *testing.T) {
	hostname, _ := os.Hostname()
	s := httptest.NewServer(via.Via(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		require.Equal(t, "1.1 "+hostname, r.Header.Get("via"))
		rw.WriteHeader(http.StatusNoContent)
	})))
	defer s.Close()

	_, err := http.Get(s.URL)
	require.NoError(t, err)
}
