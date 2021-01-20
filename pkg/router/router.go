package router

import (
	"net/http"
	"sync"
)

// Router is a router to dispatch proxy requests to proper handlers according to method and host rules.
//
// Zero value of Router is a usable proxy server in the sense it will return valid HTTP responses. It will not forward
// any requests to upstream or target servers though.
type Router struct {
	// Default specifies handler to serve non-CONNECT proxy requests. If not set, NotFound will be used.
	Default http.Handler

	// Connect sets fallback CONNECT handler which will be used if no host matches. If no fallback handler specified,
	// MethodNotAllowed will be used as a fallback.
	Connect http.Handler

	// NotFound sets handler to serve non-proxy requests. If not set, http.NotFound will be used.
	NotFound http.Handler

	matchers []matcher

	once sync.Once
}

func (r *Router) init() {
	if r.Default == nil {
		r.Default = NotFound
	}
	if r.Connect == nil {
		r.Connect = MethodNotAllowed
	}
	if r.NotFound == nil {
		r.NotFound = NotFound
	}
}

// HandleConnectHost sets handler to serve CONNECT requests for target hosts.
//
// Hostname specification:
//  - `example.com` matches exactly the host name
//  - `www.example.com` matches exactly the host name as well
//  - `.example.com` matches both `example.com` and all of it's subdomains
//
// Patterns will be matched exactly in the order they were added. The pattern that matches aborts matching cycle. E.g.
//
//      r.HandleConnectHost(".example.com", A)
//      r.HandleConnectHost("example.com", B)
//
//  would match handler A for the target host `example.com`
//
func (r *Router) HandleConnectHost(host string, handler http.Handler) {
	r.matchers = append(r.matchers, matcher{
		tpl:     host,
		handler: handler,
	})
}

func (r *Router) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	r.once.Do(r.init)
	var h http.Handler
	switch {
	case rq.Method == http.MethodConnect:
		h = r.Connect
		if r.matchers != nil {
			for i := range r.matchers {
				if r.matchers[i].matches(rq.URL.Hostname()) {
					h = r.matchers[i].handler
					break
				}
			}
		}
	case rq.URL.Host != "":
		h = r.Default
	default:
		h = r.NotFound
	}
	h.ServeHTTP(rw, rq)
}

// NotFound is the handler which returns 404 for any request
var NotFound = http.HandlerFunc(http.NotFound)

// MethodNotAllowed is the handler which returns 405 for any request
var MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
})
