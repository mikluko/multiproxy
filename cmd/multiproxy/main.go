package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/proxy"
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

// parseFlags reads the command line.
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

// newHandler builds the proxy described by cfg, signing MITM certificates with ca, logging each request through
// access and server.
func newHandler(cfg config, ca *tls.Certificate, access, server *slog.Logger) (http.Handler, error) {
	if cfg.noAccessLog {
		access = nil
	}
	var middleware []func(http.Handler) http.Handler
	if len(cfg.headerRules) > 0 {
		middleware = append(middleware, headers.Rewrite(cfg.headerRules...))
	}
	return proxy.New(proxy.Config{
		MITM:   patterns(cfg.mitmHosts),
		Tunnel: patterns(cfg.tunnelHosts),
		Issuer: &issuer.Cache{Issuer: &issuer.SelfSignedCA{
			Cert:         ca,
			KeyAlgorithm: cfg.leafKey,
			Validity:     cfg.leafValidity,
		}},
		Middleware:      middleware,
		NoVia:           cfg.noVia,
		NoXForwardedFor: cfg.noXForwardedFor,
		Access:          access,
		Server:          server,
	})
}

// patterns splits a comma-separated flag value into host patterns.
func patterns(flag string) []string {
	if flag == "" {
		return nil
	}
	return strings.Split(flag, ",")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command: it returns the exit status, 2 for a usage error and 1 for any other failure. Unless
// -print-ca is given, it returns when a listener fails, or with 0 on SIGINT or SIGTERM.
func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	access, server, shutdown, err := setupTelemetry(ctx, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	l := server.With("logger", "cli")
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			l.Log(ctx, exportErrorLevel(), "telemetry shutdown", "error", err)
		}
	}()
	fail := func(err error) int {
		l.Error("exiting", "error", err)
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

	h, err := newHandler(cfg, ca, access, server)
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
		l.Info("starting SOCKS5", "listen", socksListener.Addr().String())
		go func() { errc <- (&socks5.Server{Handler: h}).Serve(socksListener) }()
	}
	l.Info("starting", "listen", httpListener.Addr().String())
	go func() { errc <- http.Serve(httpListener, h) }()
	select {
	case err := <-errc:
		return fail(err)
	case <-ctx.Done():
		l.Info("stopping")
		return 0
	}
}

// shutdownTimeout bounds the flush of telemetry on exit.
const shutdownTimeout = 5 * time.Second
