package xforwardedfor_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/akabos/multiproxy/pkg/middleware/xforwardedfor"
)

func TestXForwardedFor(t *testing.T) {
	s := httptest.NewServer(xforwardedfor.XForwardedFor(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		require.Equal(t, "192.0.2.1, 127.0.0.1", r.Header.Get("x-forwarded-for"))
		rw.WriteHeader(http.StatusNoContent)
	})))
	defer s.Close()

	rq, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	rq.Header.Add("X-Forwarded-For", "192.0.2.1")

	_, err := http.DefaultTransport.RoundTrip(rq)
	require.NoError(t, err)
}
