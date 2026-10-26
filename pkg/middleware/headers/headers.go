// Package headers rewrites the headers of proxied requests per target host.
package headers

import (
	"net/http"
	"slices"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
	"sarak.sh/mikluko/multiproxy/pkg/router"
)

// Rule changes the headers of requests to hosts matching Host.
type Rule struct {
	// Host is a pattern under the syntax of router.MatchHost.
	Host string

	// Set replaces each named header with the given values, adding it where absent.
	Set http.Header

	// Delete strips the named headers.
	Delete []string

	// SetFunc returns headers to set on the request it is given, replacing each named header as Set does. It is
	// called for every matching request, so a function wrapping a remote fetch keeps its own cache, and it must not
	// modify the request. An error answers the request with 502 Bad Gateway and it is not forwarded.
	SetFunc func(rq *http.Request) (http.Header, error)
}

// Rewrite returns a middleware applying every rule whose Host matches the request's target host, in order.
// Within a rule, Delete applies first, then Set, then SetFunc.
func Rewrite(rules ...Rule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			host := rq.URL.Hostname()
			for _, r := range rules {
				if !router.MatchHost(r.Host, host) {
					continue
				}
				for _, name := range r.Delete {
					rq.Header.Del(name)
				}
				set(rq.Header, r.Set)
				if r.SetFunc == nil {
					continue
				}
				h, err := r.SetFunc(rq)
				if err != nil {
					log.Error(rq, "header rewrite failed", "host", host, "error", err)
					http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
					return
				}
				set(rq.Header, h)
			}
			next.ServeHTTP(rw, rq)
		})
	}
}

func set(dst, src http.Header) {
	for name, values := range src {
		dst[http.CanonicalHeaderKey(name)] = slices.Clone(values)
	}
}
