package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/justinas/alice"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/via"
	"sarak.sh/mikluko/multiproxy/pkg/router"
	"sarak.sh/mikluko/multiproxy/pkg/socks5"
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
	caCert          string
	caKey           string
	caName          string
	caOrg           string
	printCA         bool
	headerRules     []headers.Rule
	socks           string
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
	fs.StringVar(&cfg.socks, "socks", "", "interface and port of a SOCKS5 listener routed by the same rules; none when empty")
	fs.BoolVar(&cfg.noVia, "novia", false, "proxy will not add/update Via header")
	fs.BoolVar(&cfg.noXForwardedFor, "noxforwardedfor", false, "proxy will not add/update X-Forwarded-For header")
	fs.BoolVar(&cfg.noAccessLog, "noaccesslog", false, "disable access logging")
	fs.StringVar(&cfg.mitmHosts, "mitm", "", "coma-separated list of hostnames CONNECT requests to which will be handled with MITM proxy")
	fs.StringVar(&cfg.tunnelHosts, "tunnel", "", "coma-separated list of host names CONNECT requests to which will be handled with tunnel proxy")
	fs.StringVar(&leafKey, "leaf-key", "rsa", "key algorithm of MITM certificates: rsa or ecdsa")
	fs.DurationVar(&cfg.leafValidity, "leaf-validity", issuer.DefaultIssuerValidity, "validity of MITM certificates")
	fs.StringVar(&cfg.caCert, "ca-cert", "", "PEM file of the CA certificate signing MITM certificates; created with -ca-key when neither exists")
	fs.StringVar(&cfg.caKey, "ca-key", "", "PEM file of the CA private key")
	fs.StringVar(&cfg.caName, "ca-name", issuer.DefaultIssuerRootTmpl.Subject.CommonName, "common name of a generated CA")
	fs.StringVar(&cfg.caOrg, "ca-org", issuer.DefaultIssuerRootTmpl.Subject.Organization[0], "organization of a generated CA")
	fs.BoolVar(&cfg.printCA, "print-ca", false, "print the CA certificate as PEM and exit")
	fs.Var(headerFlag{rules: &cfg.headerRules}, "set-header", "HOST=Name: value sets a header on plain-HTTP and MITM requests to HOST; repeatable")
	fs.Var(headerFlag{rules: &cfg.headerRules, del: true}, "del-header", "HOST=Name strips a header from plain-HTTP and MITM requests to HOST; repeatable")
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
	if (cfg.caCert == "") != (cfg.caKey == "") {
		return config{}, errors.New("-ca-cert and -ca-key: give both or neither")
	}
	if cfg.mitmHosts == "" && cfg.tunnelHosts == "" {
		cfg.tunnelHosts = "*"
	}
	return cfg, nil
}

// loadCA returns the CA that signs MITM certificates: read from -ca-cert and -ca-key, created there when neither
// exists, or generated in memory when neither flag is given.
func loadCA(cfg config) (*tls.Certificate, error) {
	tmpl := issuer.RootTemplate(cfg.caName, cfg.caOrg, caValidity)
	if cfg.caCert == "" {
		return issuer.NewRoot(tmpl, issuer.DefaultIssuerRootBitSize, rand.Reader)
	}
	return issuer.LoadOrCreate(cfg.caCert, cfg.caKey, tmpl)
}

// caValidity is the validity of a CA the command generates.
const caValidity = 10 * 365 * 24 * time.Hour

// writeCA writes the certificate of ca to w as PEM.
func writeCA(w io.Writer, ca *tls.Certificate) error {
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})
}

// newHandler builds the proxy described by cfg, signing MITM certificates with ca, writing access logs to accessw
// and server logs to serverw.
func newHandler(cfg config, ca *tls.Certificate, accessw, serverw io.Writer) (http.Handler, error) {
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
	if len(cfg.headerRules) > 0 {
		httpMiddleware = append(httpMiddleware, headers.Rewrite(cfg.headerRules...))
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
			Cert:         ca,
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command: it returns the exit status, 2 for a usage error and 1 for any other failure. Unless
// -print-ca is given, it returns only when a listener fails.
func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	l := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(log.DefaultServerLogEncoderConfig()),
		zapcore.AddSync(stderr),
		zapcore.InfoLevel,
	)).Named("cli")
	fail := func(err error) int {
		l.Error("", zap.Error(err))
		return 1
	}

	ca, err := loadCA(cfg)
	if err != nil {
		return fail(err)
	}
	if cfg.printCA {
		if err := writeCA(stdout, ca); err != nil {
			return fail(err)
		}
		return 0
	}

	h, err := newHandler(cfg, ca, stdout, stderr)
	if err != nil {
		return fail(err)
	}

	errc := make(chan error, 2)
	httpListener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fail(err)
	}
	defer httpListener.Close()
	if cfg.socks != "" {
		socksListener, err := net.Listen("tcp", cfg.socks)
		if err != nil {
			return fail(err)
		}
		defer socksListener.Close()
		l.Info("starting SOCKS5", zap.String("listen", socksListener.Addr().String()))
		go func() { errc <- (&socks5.Server{Handler: h}).Serve(socksListener) }()
	}
	l.Info("starting", zap.String("listen", httpListener.Addr().String()))
	go func() { errc <- http.Serve(httpListener, h) }()
	return fail(<-errc)
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
