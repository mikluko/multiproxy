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
	//
	// A non-CONNECT request reaches Default only where a CONNECT host pattern matches its host or Connect is set;
	// any other is answered by Forbidden.
	Default http.Handler

	// Connect sets fallback CONNECT handler which will be used if no host matches. If no fallback handler specified,
	// MethodNotAllowed will be used as a fallback.
	Connect http.Handler

	// NotFound sets handler to serve non-proxy requests. If not set, http.NotFound will be used.
	NotFound http.Handler

	matchers    []matcher
	hasFallback bool

	once sync.Once
}

func (r *Router) init() {
	r.hasFallback = r.Connect != nil
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
// The pattern `*` sets Connect, the fallback for hosts no other pattern matches, whenever it is added.
func (r *Router) HandleConnectHost(host string, handler http.Handler) {
	if host == "*" {
		r.Connect = handler
		return
	}
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
		if m := r.match(rq.URL.Hostname()); m != nil {
			h = m
		}
	case rq.URL.Host != "":
		h = Forbidden
		if r.hasFallback || r.match(rq.URL.Hostname()) != nil {
			h = r.Default
		}
	default:
		h = r.NotFound
	}
	h.ServeHTTP(rw, rq)
}

// match returns the handler of the first host pattern matching hostname, or nil.
func (r *Router) match(hostname string) http.Handler {
	for i := range r.matchers {
		if r.matchers[i].matches(hostname) {
			return r.matchers[i].handler
		}
	}
	return nil
}

// Forbidden is the handler which returns 403 for any request
var Forbidden = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
})

// NotFound is the handler which returns 404 for any request
var NotFound = http.HandlerFunc(http.NotFound)

// MethodNotAllowed is the handler which returns 405 for any request
var MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
})
