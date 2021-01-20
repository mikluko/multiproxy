package xforwardedfor

import (
	"net"
	"net/http"
	"strings"
)

// XForwardedFor is a middleware which appends X-Forwarded-For header to outgoing requests as described in
// https://en.wikipedia.org/wiki/X-Forwarded-For
//
func XForwardedFor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		host, _, err := net.SplitHostPort(rq.RemoteAddr)
		if err != nil {
			panic("invalid remote addr on request")
		}
		var b strings.Builder
		orig := rq.Header.Get("x-forwarded-for")
		if orig != "" {
			_, _ = b.WriteString(orig)
			_, _ = b.WriteString(", ")
		}
		b.WriteString(host)
		rq.Header.Set("x-forwarded-for", b.String())
		next.ServeHTTP(rw, rq)
	})
}
