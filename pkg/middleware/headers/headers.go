// Package headers rewrites the headers of proxied requests per target host.
package headers

import (
	"net/http"
	"slices"

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
}

// Rewrite returns a middleware applying every rule whose Host matches the request's target host, in order.
// Within a rule, Delete applies before Set.
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
				for name, values := range r.Set {
					rq.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
				}
			}
			next.ServeHTTP(rw, rq)
		})
	}
}
