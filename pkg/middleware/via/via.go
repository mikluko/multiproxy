package via

import (
	"net/http"
	"os"
	"strings"
)

// Middleware is a middleware constructor. The middleware appends Via header outgoing requests as defined in RFC2616
// https://tools.ietf.org/html/rfc2616#section-14.45.
//
func Middleware(ident string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			var b strings.Builder
			orig := rq.Header.Get("via")
			if orig != "" {
				_, _ = b.WriteString(orig)
				_, _ = b.WriteString(", ")
			}
			b.WriteString("1.1 ")
			b.WriteString(ident)
			rq.Header.Set("via", b.String())
			next.ServeHTTP(rw, rq)
		})
	}
}

// Via is a middleware which appends Via header to outgoing requests and uses host name for the server indent.
//
func Via(next http.Handler) http.Handler {
	hostname, _ := os.Hostname()
	return Middleware(hostname)(next)
}
