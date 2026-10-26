package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/justinas/alice"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/via"
	"sarak.sh/mikluko/multiproxy/pkg/router"
)

type config struct {
	listen          string
	noVia           bool
	noXForwardedFor bool
	noAccessLog     bool
	mitmHosts       string
	tunnelHosts     string
	leafKey         x509.PublicKeyAlgorithm
	leafValidity    time.Duration
}

// parseFlags reads the command line. With neither -mitm nor -tunnel given, every CONNECT host is tunnelled.
func parseFlags(args []string, output io.Writer) (config, error) {
	var (
		cfg     config
		leafKey string
		fs      = flag.NewFlagSet("multiproxy", flag.ContinueOnError)
	)
	fs.SetOutput(output)
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:8080", "interface and port to bind server to")
	fs.BoolVar(&cfg.noVia, "novia", false, "proxy will not add/update Via header")
	fs.BoolVar(&cfg.noXForwardedFor, "noxforwardedfor", false, "proxy will not add/update X-Forwarded-For header")
	fs.BoolVar(&cfg.noAccessLog, "noaccesslog", false, "disable access logging")
	fs.StringVar(&cfg.mitmHosts, "mitm", "", "coma-separated list of hostnames CONNECT requests to which will be handled with MITM proxy")
	fs.StringVar(&cfg.tunnelHosts, "tunnel", "", "coma-separated list of host names CONNECT requests to which will be handled with tunnel proxy")
	fs.StringVar(&leafKey, "leaf-key", "rsa", "key algorithm of MITM certificates: rsa or ecdsa")
	fs.DurationVar(&cfg.leafValidity, "leaf-validity", issuer.DefaultIssuerValidity, "validity of MITM certificates")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	switch leafKey {
	case "rsa":
		cfg.leafKey = x509.RSA
	case "ecdsa":
		cfg.leafKey = x509.ECDSA
	default:
		return config{}, fmt.Errorf("-leaf-key: want rsa or ecdsa, got %q", leafKey)
	}
	if cfg.leafValidity <= 0 {
		return config{}, fmt.Errorf("-leaf-validity: want a positive duration, got %s", cfg.leafValidity)
	}
	if cfg.mitmHosts == "" && cfg.tunnelHosts == "" {
		cfg.tunnelHosts = "*"
	}
	return cfg, nil
}

// newHandler builds the proxy described by cfg, writing access logs to accessw and server logs to serverw.
func newHandler(cfg config, accessw, serverw io.Writer) (http.Handler, error) {
	if cfg.noAccessLog {
		accessw = io.Discard
	}
	lmw := log.Middleware(accessw, serverw, zapcore.InfoLevel)

	named := func(name string) alice.Constructor {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
				log.Named(rq, name)
				next.ServeHTTP(rw, rq)
			})
		}
	}

	httpMiddleware := []alice.Constructor{lmw, named("http")}
	if !cfg.noVia {
		httpMiddleware = append(httpMiddleware, via.Via)
	}
	mux := &router.Router{
		Default: alice.New(httpMiddleware...).Then(&handlers.HTTPHandler{
			NoXForwardedFor: cfg.noXForwardedFor,
		}),
	}

	mitmHandler := &handlers.MITMHandler{
		Handler: alice.New(httpMiddleware...).Then(&handlers.HTTPHandler{
			NoXForwardedFor: cfg.noXForwardedFor,
		}),
		Issuer: &issuer.SelfSignedCA{
			KeyAlgorithm: cfg.leafKey,
			Validity:     cfg.leafValidity,
		},
	}
	if err := registerHandler(mux, alice.New(lmw, named("mitm")).Then(mitmHandler), cfg.mitmHosts); err != nil {
		return nil, err
	}

	tunnelHandler := &handlers.Tunnel{
		DialTimeout: 5 * time.Second,
	}
	if err := registerHandler(mux, alice.New(lmw, named("tunnel")).Then(tunnelHandler), cfg.tunnelHosts); err != nil {
		return nil, err
	}

	return mux, nil
}

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	l := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(log.DefaultServerLogEncoderConfig()),
		zapcore.AddSync(os.Stderr),
		zapcore.InfoLevel,
	)).Named("cli")

	h, err := newHandler(cfg, os.Stdout, os.Stderr)
	if err != nil {
		l.Fatal("", zap.Error(err))
	}

	l.Info("starting", zap.String("listen", cfg.listen))
	if err := http.ListenAndServe(cfg.listen, h); err != nil {
		l.Fatal("", zap.Error(err))
	}
}

func registerHandler(mux *router.Router, handler http.Handler, hostnames string) error {
	if hostnames == "" {
		return nil
	}
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
