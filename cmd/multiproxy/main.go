package main

import (
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/justinas/alice"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/akabos/multiproxy/pkg/handlers"
	"github.com/akabos/multiproxy/pkg/middleware/log"
	"github.com/akabos/multiproxy/pkg/middleware/via"
	"github.com/akabos/multiproxy/pkg/router"
)

var (
	optListen          = flag.String("listen", "127.0.0.1:8080", "interface and port to bind server to")
	optNoVia           = flag.Bool("novia", false, "proxy will not add/update Via header")
	optNoXForwardedFor = flag.Bool("noxforwardedfor", false, "proxy will not add/update X-Forwarded-For header")
	optNoAccessLog     = flag.Bool("noaccesslog", false, "disable access logging")
	optMitmHostnames   = flag.String("mitm", "", "coma-separated list of hostnames CONNECT requests to which will be handled with MITM proxy")
	optTunnelHostnames = flag.String("tunnel", "", "coma-separated list of host names CONNECT requests to which will be handled with tunnel proxy")
)

func init() {
	flag.Parse()
	if *optMitmHostnames == "" && *optTunnelHostnames == "" {
		*optTunnelHostnames = "*"
	}
}

func main() {
	var (
		accessw io.Writer = os.Stdout
		serverw io.Writer = os.Stderr
	)
	if *optNoAccessLog {
		accessw = ioutil.Discard
	}

	var (
		err error
		l   = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(log.DefaultServerLogEncoderConfig()),
			zapcore.AddSync(serverw),
			zapcore.InfoLevel,
		)).Named("cli")
		lmw = log.Middleware(accessw, serverw, zapcore.InfoLevel)
	)

	var httpMiddleware = []alice.Constructor{
		lmw,
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				log.Named(rq, "http")
				next.ServeHTTP(rw, rq)
			})
		},
	}
	if !*optNoVia {
		httpMiddleware = append(httpMiddleware, via.Via)
	}
	var mux = &router.Router{
		Default: alice.New(httpMiddleware...).Then(&handlers.HTTPHandler{
			NoXForwardedFor: *optNoXForwardedFor,
		}),
	}

	var mitmHandler http.Handler = &handlers.MITMHandler{
		Handler: alice.New(httpMiddleware...).Then(&handlers.HTTPHandler{
			NoXForwardedFor: *optNoXForwardedFor,
		}),
	}
	var mitmMiddleware = []alice.Constructor{
		lmw,
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				log.Named(rq, "mitm")
				next.ServeHTTP(rw, rq)
			})
		},
	}
	err = registerHandler(mux, alice.New(mitmMiddleware...).Then(mitmHandler), *optMitmHostnames)
	if err != nil {
		l.Fatal("", zap.Error(err))
	}

	var tunnelHandler http.Handler = &handlers.Tunnel{
		DialTimeout: 5 * time.Second,
	}
	var tunnelMiddleware = []alice.Constructor{
		lmw,
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				log.Named(rq, "tunnel")
				next.ServeHTTP(rw, rq)
			})
		},
	}
	err = registerHandler(mux, alice.New(tunnelMiddleware...).Then(tunnelHandler), *optTunnelHostnames)
	if err != nil {
		l.Fatal("", zap.Error(err))
	}

	l.Info("starting", zap.String("listen", *optListen))

	err = http.ListenAndServe(*optListen, mux)
	if err != nil {
		l.Fatal("", zap.Error(err))
	}
}

func registerHandler(mux *router.Router, handler http.Handler, hostnames string) error {
	for _, hostname := range strings.Split(hostnames, ",") {
		hostname = strings.TrimSpace(hostname)
		if hostname != "*" {
			mux.HandleConnectHost(hostname, handler)
			continue
		}
		if mux.Connect != nil {
			return errors.New("multiple fallback handlers specified")
		}
		mux.Connect = handler
	}
	return nil
}
