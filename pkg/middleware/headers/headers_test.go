package headers_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
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

func TestRewrite_SetFunc(t *testing.T) {
	newRequest := func(target string) *http.Request {
		rq := httptest.NewRequest(http.MethodGet, target, nil)
		rq.Header.Set("Authorization", "Bearer client")
		return rq
	}

	t.Run("sets the returned headers, replacing existing ones", func(t *testing.T) {
		got := seen(t, newRequest("http://api.example.com/repos/alice/x"), headers.Rule{
			Host: "api.example.com",
			SetFunc: func(rq *http.Request) (http.Header, error) {
				owner := strings.Split(rq.URL.Path, "/")[2]
				return http.Header{"authorization": {"Bearer " + owner}}, nil
			},
		})
		require.Equal(t, []string{"Bearer alice"}, got.Values("Authorization"))
	})
	t.Run("runs after Delete and Set", func(t *testing.T) {
		var during http.Header
		got := seen(t, newRequest("http://example.com/"), headers.Rule{
			Host:   "example.com",
			Delete: []string{"Authorization"},
			Set:    http.Header{"X-A": {"set"}, "X-B": {"set"}},
			SetFunc: func(rq *http.Request) (http.Header, error) {
				during = rq.Header.Clone()
				return http.Header{"X-B": {"func"}}, nil
			},
		})
		require.Empty(t, during.Values("Authorization"))
		require.Equal(t, "set", during.Get("X-A"))
		require.Equal(t, "set", got.Get("X-A"))
		require.Equal(t, "func", got.Get("X-B"))
	})
	t.Run("fails closed on error", func(t *testing.T) {
		called := false
		h := headers.Rewrite(headers.Rule{
			Host: "example.com",
			SetFunc: func(*http.Request) (http.Header, error) {
				return nil, errors.New("secret store unavailable")
			},
		})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, newRequest("http://example.com/"))
		require.Equal(t, http.StatusBadGateway, rw.Code)
		require.False(t, called)
		require.NotContains(t, rw.Body.String(), "secret store")
	})
	t.Run("gets the request context", func(t *testing.T) {
		type key struct{}
		var value any
		rq := newRequest("http://example.com/")
		rq = rq.WithContext(context.WithValue(rq.Context(), key{}, "carried"))
		seen(t, rq, headers.Rule{
			Host: "example.com",
			SetFunc: func(rq *http.Request) (http.Header, error) {
				value = rq.Context().Value(key{})
				return nil, nil
			},
		})
		require.Equal(t, "carried", value)
	})
	t.Run("nil headers change nothing", func(t *testing.T) {
		got := seen(t, newRequest("http://example.com/"), headers.Rule{
			Host:    "example.com",
			SetFunc: func(*http.Request) (http.Header, error) { return nil, nil },
		})
		require.Equal(t, "Bearer client", got.Get("Authorization"))
	})
	t.Run("is not called for other hosts", func(t *testing.T) {
		seen(t, newRequest("http://example.net/"), headers.Rule{
			Host: "example.com",
			SetFunc: func(*http.Request) (http.Header, error) {
				t.Fatal("SetFunc called for a host the rule does not match")
				return nil, nil
			},
		})
	})
}

func TestRewrite_SetFuncErrorIsLogged(t *testing.T) {
	var server bytes.Buffer
	h := log.Middleware(slog.New(slog.DiscardHandler), slog.New(slog.NewJSONHandler(&server, nil)))(
		headers.Rewrite(headers.Rule{
			Host:    "example.com",
			SetFunc: func(*http.Request) (http.Header, error) { return nil, errors.New("secret store unavailable") },
		})(http.NotFoundHandler()),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	require.Contains(t, server.String(), `"msg":"header rewrite failed"`)
	require.Contains(t, server.String(), `"error":"secret store unavailable"`)
	require.Contains(t, server.String(), `"host":"example.com"`)
}
