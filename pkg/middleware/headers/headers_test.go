package headers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
)

// seen runs rq through the rewrite and returns the headers the next handler received.
func seen(t *testing.T, rq *http.Request, rules ...headers.Rule) http.Header {
	t.Helper()
	var got http.Header
	h := headers.Rewrite(rules...)(http.HandlerFunc(func(_ http.ResponseWriter, rq *http.Request) {
		got = rq.Header.Clone()
	}))
	h.ServeHTTP(httptest.NewRecorder(), rq)
	return got
}

func TestRewrite(t *testing.T) {
	newRequest := func(target string) *http.Request {
		rq := httptest.NewRequest(http.MethodGet, target, nil)
		rq.Header.Set("Authorization", "Bearer client")
		rq.Header.Set("Cookie", "a=b")
		return rq
	}

	t.Run("replaces a header on a matching host", func(t *testing.T) {
		got := seen(t, newRequest("https://api.example.com/v1"), headers.Rule{
			Host: "api.example.com",
			Set:  http.Header{"Authorization": {"Bearer proxy"}},
		})
		require.Equal(t, []string{"Bearer proxy"}, got.Values("Authorization"))
	})
	t.Run("adds a header that was absent", func(t *testing.T) {
		got := seen(t, newRequest("http://example.com/"), headers.Rule{
			Host: "example.com",
			Set:  http.Header{"X-Env": {"test"}},
		})
		require.Equal(t, "test", got.Get("X-Env"))
	})
	t.Run("strips a header", func(t *testing.T) {
		got := seen(t, newRequest("http://example.com/"), headers.Rule{
			Host:   ".example.com",
			Delete: []string{"cookie"},
		})
		require.Empty(t, got.Values("Cookie"))
		require.Equal(t, "Bearer client", got.Get("Authorization"))
	})
	t.Run("leaves other hosts alone", func(t *testing.T) {
		got := seen(t, newRequest("http://example.net/"), headers.Rule{
			Host:   "example.com",
			Set:    http.Header{"Authorization": {"Bearer proxy"}},
			Delete: []string{"Cookie"},
		})
		require.Equal(t, "Bearer client", got.Get("Authorization"))
		require.Equal(t, "a=b", got.Get("Cookie"))
	})
	t.Run("applies every matching rule in order", func(t *testing.T) {
		got := seen(t, newRequest("http://www.example.com/"),
			headers.Rule{Host: "*", Set: http.Header{"X-A": {"1"}, "X-B": {"1"}}},
			headers.Rule{Host: ".example.com", Set: http.Header{"X-B": {"2"}}},
		)
		require.Equal(t, "1", got.Get("X-A"))
		require.Equal(t, "2", got.Get("X-B"))
	})
	t.Run("does not alias rule values", func(t *testing.T) {
		rule := headers.Rule{Host: "*", Set: http.Header{"X-A": {"1"}}}
		h := headers.Rewrite(rule)(http.HandlerFunc(func(_ http.ResponseWriter, rq *http.Request) {
			rq.Header.Add("X-A", "2")
		}))
		h.ServeHTTP(httptest.NewRecorder(), newRequest("http://example.com/"))
		require.Equal(t, []string{"1"}, rule.Set["X-A"])
	})
}
