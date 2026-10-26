// Package proxy assembles the router, handlers and middleware of this module into one proxy.
package proxy

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/via"
	"sarak.sh/mikluko/multiproxy/pkg/router"
)

// Config describes a proxy. The zero value tunnels every CONNECT request and proxies plain HTTP to any host.
type Config struct {
	// MITM and Tunnel are host patterns, under the syntax of router.MatchHost, whose CONNECT requests are intercepted
	// and tunnelled. MITM patterns are tried first. "*" in one of the two is the fallback for hosts no pattern
	// matches. A host no pattern and no fallback matches is refused, plain HTTP included.
	//
	// With both empty, every host is tunnelled.
	MITM, Tunnel []string

	// Issuer issues the certificates of intercepted hosts.
	//
	// If nil, an issuer.Cache of an issuer.SelfSignedCA will be used.
	Issuer issuer.Issuer

	// Middleware wraps the handling of every plain-HTTP request and every request intercepted by MITM, the first
	// outermost.
	Middleware []func(http.Handler) http.Handler

	// NoVia leaves out the Via header, and NoXForwardedFor the X-Forwarded-For header.
	NoVia, NoXForwardedFor bool

	// Access and Server log each request, as log.Middleware does.
	//
	// If nil, nothing is logged.
	Access, Server *slog.Logger

	// Transport sends plain-HTTP and intercepted requests upstream.
	//
	// If nil, handlers.DefaultTransport will be used, which verifies upstream TLS certificates against the system
	// roots.
	Transport http.RoundTripper

	// TunnelDialTimeout bounds connecting to a tunnel target.
	//
	// If 0, DefaultTunnelDialTimeout will be used.
	TunnelDialTimeout time.Duration
}

// DefaultTunnelDialTimeout is the default bound on connecting to a tunnel target.
const DefaultTunnelDialTimeout = 5 * time.Second

// New returns the proxy cfg describes. Each request, and each request intercepted by MITM, is a server span of the
// global tracer provider, and each upstream request a client span propagated to the upstream server. It fails where
// both MITM and Tunnel hold "*".
func New(cfg Config) (http.Handler, error) {
	if len(cfg.MITM) == 0 && len(cfg.Tunnel) == 0 {
		cfg.Tunnel = []string{"*"}
	}
	if contains(cfg.MITM, "*") && contains(cfg.Tunnel, "*") {
		return nil, errors.New(`proxy: "*" in both MITM and Tunnel`)
	}
	if cfg.Issuer == nil {
		cfg.Issuer = &issuer.Cache{Issuer: &issuer.SelfSignedCA{}}
	}
	if cfg.Access == nil {
		cfg.Access = slog.New(slog.DiscardHandler)
	}
	if cfg.Server == nil {
		cfg.Server = slog.New(slog.DiscardHandler)
	}
	if cfg.Transport == nil {
		cfg.Transport = handlers.DefaultTransport
	}
	if cfg.TunnelDialTimeout == 0 {
		cfg.TunnelDialTimeout = DefaultTunnelDialTimeout
	}

	logged := log.Middleware(cfg.Access, cfg.Server)
	upstream := otelhttp.NewTransport(cfg.Transport)

	httpChain := alice.New(logged, named("http"))
	if !cfg.NoVia {
		httpChain = httpChain.Append(via.Via)
	}
	for _, m := range cfg.Middleware {
		httpChain = httpChain.Append(alice.Constructor(m))
	}
	plain := func() http.Handler {
		return httpChain.Then(&handlers.HTTPHandler{Transport: upstream, NoXForwardedFor: cfg.NoXForwardedFor})
	}

	r := &router.Router{Default: plain()}
	mitm := alice.New(logged, named("mitm")).Then(&handlers.MITMHandler{
		Handler: otelhttp.NewHandler(plain(), "mitm", spanName),
		Issuer:  cfg.Issuer,
	})
	tunnel := alice.New(logged, named("tunnel")).Then(&handlers.Tunnel{DialTimeout: cfg.TunnelDialTimeout})
	for _, host := range cfg.MITM {
		r.HandleConnectHost(strings.TrimSpace(host), mitm)
	}
	for _, host := range cfg.Tunnel {
		r.HandleConnectHost(strings.TrimSpace(host), tunnel)
	}

	return otelhttp.NewHandler(r, "proxy", spanName), nil
}

// named appends name to the logger name of each request.
func named(name string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
			log.Named(rq, name)
			next.ServeHTTP(rw, rq)
		})
	}
}

// spanName names a span after the request method, and after the target too for CONNECT.
var spanName = otelhttp.WithSpanNameFormatter(func(_ string, rq *http.Request) string {
	if rq.Method == http.MethodConnect {
		return "CONNECT " + rq.Host
	}
	return rq.Method
})

func contains(patterns []string, want string) bool {
	for _, p := range patterns {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}
