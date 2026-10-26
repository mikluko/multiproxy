package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/socks5"
)

func TestMain(m *testing.M) {
	// Tests that need the SDK enable it themselves; the rest must not export to a collector on localhost.
	_ = os.Setenv("OTEL_SDK_DISABLED", "true")
	os.Exit(m.Run())
}

func TestParseFlags(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := parseFlags(nil, io.Discard)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:8080", cfg.listen)
		require.Empty(t, cfg.tunnelHosts)
		require.Empty(t, cfg.mitmHosts)
		require.Equal(t, x509.RSA, cfg.leafKey)
		require.Equal(t, issuer.DefaultIssuerValidity, cfg.leafValidity)
	})
	t.Run("mitm alone tunnels nothing", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-mitm", "example.com"}, io.Discard)
		require.NoError(t, err)
		require.Equal(t, "example.com", cfg.mitmHosts)
		require.Empty(t, cfg.tunnelHosts)
	})
	t.Run("leaf key and validity", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-leaf-key", "ecdsa", "-leaf-validity", "48h"}, io.Discard)
		require.NoError(t, err)
		require.Equal(t, x509.ECDSA, cfg.leafKey)
		require.Equal(t, 48*time.Hour, cfg.leafValidity)
	})
	t.Run("unknown leaf key", func(t *testing.T) {
		_, err := parseFlags([]string{"-leaf-key", "dsa"}, io.Discard)
		require.ErrorContains(t, err, "-leaf-key")
	})
	t.Run("non-positive leaf validity", func(t *testing.T) {
		_, err := parseFlags([]string{"-leaf-validity", "0s"}, io.Discard)
		require.ErrorContains(t, err, "-leaf-validity")
	})
	t.Run("ca-cert without ca-key", func(t *testing.T) {
		_, err := parseFlags([]string{"-ca-cert", "ca.pem"}, io.Discard)
		require.ErrorContains(t, err, "-ca-key")
	})
	t.Run("header rules keep their order", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-set-header", "a.test=X-A: 1", "-del-header", "b.test=X-B", "-set-header", "c.test= x-c :  2 "}, io.Discard)
		require.NoError(t, err)
		require.Equal(t, []headers.Rule{
			{Host: "a.test", Set: http.Header{"X-A": {"1"}}},
			{Host: "b.test", Delete: []string{"X-B"}},
			{Host: "c.test", Set: http.Header{"X-C": {"2"}}},
		}, cfg.headerRules)
	})
	for _, bad := range [][]string{
		{"-set-header", "X-A: 1"},
		{"-set-header", "=X-A: 1"},
		{"-set-header", "a.test=X-A"},
		{"-set-header", "a.test=Bad Name: 1"},
		{"-del-header", "a.test="},
		{"-del-header", "a.test=X:A"},
	} {
		t.Run("rejects "+bad[0]+" "+bad[1], func(t *testing.T) {
			_, err := parseFlags(bad, io.Discard)
			require.ErrorContains(t, err, bad[0])
		})
	}
	t.Run("socks", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-socks", "127.0.0.1:1080"}, io.Discard)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:1080", cfg.socks)
	})
	t.Run("help", func(t *testing.T) {
		_, err := parseFlags([]string{"-h"}, io.Discard)
		require.ErrorIs(t, err, flag.ErrHelp)
	})
}

func TestNewHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(echoVia))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(echoVia))
	defer tlsBackend.Close()

	t.Run("plain HTTP adds Via", func(t *testing.T) {
		rs := get(t, startProxy(t), backend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.NotEmpty(t, rs.Header.Get("X-Seen-Via"))
	})
	t.Run("plain HTTP without Via", func(t *testing.T) {
		rs := get(t, startProxy(t, "-novia"), backend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.Empty(t, rs.Header.Get("X-Seen-Via"))
	})
	t.Run("CONNECT is tunnelled by default", func(t *testing.T) {
		rs := get(t, startProxy(t), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.True(t, rs.TLS.PeerCertificates[0].Equal(tlsBackend.Certificate()))
	})
	t.Run("CONNECT to a -mitm host is intercepted", func(t *testing.T) {
		rs := get(t, startProxy(t, "-mitm", "127.0.0.1"), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		leaf := rs.TLS.PeerCertificates[0]
		require.Equal(t, issuer.DefaultIssuerRootTmpl.Subject.CommonName, leaf.Issuer.CommonName)
		require.IsType(t, &rsa.PublicKey{}, leaf.PublicKey)
	})
	t.Run("-leaf-key ecdsa", func(t *testing.T) {
		rs := get(t, startProxy(t, "-mitm", "127.0.0.1", "-leaf-key", "ecdsa"), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.IsType(t, &ecdsa.PublicKey{}, rs.TLS.PeerCertificates[0].PublicKey)
	})
	t.Run("CONNECT to an unlisted host is refused", func(t *testing.T) {
		p := startProxy(t, "-mitm", "example.com")
		_, err := client(p).Get(tlsBackend.URL)
		require.ErrorContains(t, err, "Method Not Allowed")
	})
	t.Run("plain HTTP to an unlisted host is refused", func(t *testing.T) {
		rs := get(t, startProxy(t, "-mitm", "example.com"), backend.URL)
		require.Equal(t, http.StatusForbidden, rs.StatusCode)
	})
	t.Run("plain HTTP to a listed host passes", func(t *testing.T) {
		rs := get(t, startProxy(t, "-tunnel", "127.0.0.1"), backend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
	})
	t.Run("-set-header on plain HTTP", func(t *testing.T) {
		rs := get(t, startProxy(t, "-set-header", "127.0.0.1=X-Test: yes"), backend.URL)
		require.Equal(t, "yes", rs.Header.Get("X-Seen-Test"))
	})
	t.Run("-set-header on an intercepted request", func(t *testing.T) {
		rs := get(t, startProxy(t, "-mitm", "127.0.0.1", "-set-header", "127.0.0.1=X-Test: yes"), tlsBackend.URL)
		require.Equal(t, "yes", rs.Header.Get("X-Seen-Test"))
	})
	t.Run("-set-header on another host", func(t *testing.T) {
		rs := get(t, startProxy(t, "-set-header", "example.com=X-Test: yes"), backend.URL)
		require.Empty(t, rs.Header.Get("X-Seen-Test"))
	})
	t.Run("-del-header", func(t *testing.T) {
		rs := get(t, startProxy(t, "-del-header", "*=Via"), backend.URL)
		require.Empty(t, rs.Header.Get("X-Seen-Via"))
	})
	t.Run("two fallback handlers", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-mitm", "*", "-tunnel", "*"}, io.Discard)
		require.NoError(t, err)
		_, err = newHandler(cfg, nil, discard, discard)
		require.Error(t, err)
	})
}

var discard = slog.New(slog.DiscardHandler)

// echoVia answers 200 and reports the Via and X-Test headers it received as X-Seen-Via and X-Seen-Test.
func echoVia(rw http.ResponseWriter, rq *http.Request) {
	rw.Header().Set("X-Seen-Via", rq.Header.Get("Via"))
	rw.Header().Set("X-Seen-Test", rq.Header.Get("X-Test"))
	rw.WriteHeader(http.StatusOK)
}

// startProxy starts the proxy configured by args and returns its URL.
func startProxy(t *testing.T, args ...string) *url.URL {
	t.Helper()
	cfg, err := parseFlags(append([]string{"-noaccesslog"}, args...), io.Discard)
	require.NoError(t, err)
	ca, err := loadCA(cfg)
	require.NoError(t, err)
	h, err := newHandler(cfg, ca, discard, discard)
	require.NoError(t, err)
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	return u
}

func client(p *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(p),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func get(t *testing.T, p *url.URL, target string) *http.Response {
	t.Helper()
	rs, err := client(p).Get(target)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rs.Body.Close() })
	_, _ = io.Copy(io.Discard, rs.Body)
	return rs
}

func TestLoadCA(t *testing.T) {
	t.Run("in memory, named by -ca-name and -ca-org", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-ca-name", "Test Root", "-ca-org", "Test Org"}, io.Discard)
		require.NoError(t, err)
		ca, err := loadCA(cfg)
		require.NoError(t, err)
		require.Equal(t, "Test Root", ca.Leaf.Subject.CommonName)
		require.Equal(t, []string{"Test Org"}, ca.Leaf.Subject.Organization)
	})
	t.Run("persisted, then trusted by a verifying client", func(t *testing.T) {
		dir := t.TempDir()
		args := []string{"-ca-cert", filepath.Join(dir, "ca.pem"), "-ca-key", filepath.Join(dir, "ca-key.pem")}
		cfg, err := parseFlags(args, io.Discard)
		require.NoError(t, err)
		first, err := loadCA(cfg)
		require.NoError(t, err)
		second, err := loadCA(cfg)
		require.NoError(t, err)
		require.True(t, first.Leaf.Equal(second.Leaf))

		backend := httptest.NewTLSServer(http.HandlerFunc(echoVia))
		defer backend.Close()
		roots := x509.NewCertPool()
		roots.AddCert(first.Leaf)
		c := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(startProxy(t, append(args, "-mitm", "127.0.0.1")...)),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		}}
		rs, err := c.Get(backend.URL)
		require.NoError(t, err)
		defer rs.Body.Close()
		require.Equal(t, http.StatusOK, rs.StatusCode)
	})
}

func TestWriteCA(t *testing.T) {
	cfg, err := parseFlags(nil, io.Discard)
	require.NoError(t, err)
	ca, err := loadCA(cfg)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, writeCA(&buf, ca))
	block, rest := pem.Decode(buf.Bytes())
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Equal(t, ca.Certificate[0], block.Bytes)
}

func TestSOCKS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(echoVia))
	defer backend.Close()
	target := strings.TrimPrefix(backend.URL, "http://")

	socks := func(t *testing.T, args ...string) string {
		t.Helper()
		cfg, err := parseFlags(append([]string{"-noaccesslog"}, args...), io.Discard)
		require.NoError(t, err)
		ca, err := loadCA(cfg)
		require.NoError(t, err)
		h, err := newHandler(cfg, ca, discard, discard)
		require.NoError(t, err)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = l.Close() })
		go func() { _ = (&socks5.Server{Handler: h}).Serve(l) }()
		return l.Addr().String()
	}

	t.Run("a tunnelled host", func(t *testing.T) {
		require.Equal(t, byte(0), socksConnect(t, socks(t), target))
	})
	t.Run("a host the rules refuse", func(t *testing.T) {
		require.Equal(t, byte(2), socksConnect(t, socks(t, "-mitm", "example.com"), target))
	})
}

// socksConnect asks the SOCKS5 server for a CONNECT to target, an IPv4 host:port, and returns the reply code.
func socksConnect(t *testing.T, server, target string) byte {
	t.Helper()
	host, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	p, err := strconv.Atoi(port)
	require.NoError(t, err)

	c, err := net.DialTimeout("tcp", server, time.Second)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	rq := append([]byte{5, 1, 0, 5, 1, 0, 1}, net.ParseIP(host).To4()...)
	rq = append(rq, byte(p>>8), byte(p))
	_, err = c.Write(rq)
	require.NoError(t, err)
	reply := make([]byte, 12)
	_, err = io.ReadFull(c, reply)
	require.NoError(t, err)
	require.Equal(t, []byte{5, 0}, reply[:2])
	return reply[3]
}

func TestRun(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		require.Equal(t, 0, run([]string{"-h"}, io.Discard, io.Discard))
	})
	t.Run("a usage error", func(t *testing.T) {
		var stderr bytes.Buffer
		require.Equal(t, 2, run([]string{"-leaf-key", "dsa"}, io.Discard, &stderr))
		require.Contains(t, stderr.String(), "-leaf-key")
	})
	t.Run("-print-ca", func(t *testing.T) {
		var stdout bytes.Buffer
		require.Equal(t, 0, run([]string{"-print-ca", "-ca-name", "Printed Root"}, &stdout, io.Discard))
		block, _ := pem.Decode(stdout.Bytes())
		require.NotNil(t, block)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		require.Equal(t, "Printed Root", cert.Subject.CommonName)
	})
	for name, args := range map[string][]string{
		"an unreadable CA":     {"-ca-cert", filepath.Join(t.TempDir(), "ca.pem"), "-ca-key", t.TempDir()},
		"two fallbacks":        {"-mitm", "*", "-tunnel", "*"},
		"a bad listen address": {"-listen", "256.0.0.1:1"},
		"a bad SOCKS address":  {"-listen", "127.0.0.1:0", "-socks", "256.0.0.1:1"},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			require.Equal(t, 1, run(args, io.Discard, &stderr))
			require.NotEmpty(t, stderr.String())
		})
	}
	t.Run("serves HTTP and SOCKS5", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(echoVia))
		defer backend.Close()
		httpAddr, socksAddr := freeAddr(t), freeAddr(t)
		go run([]string{"-noaccesslog", "-listen", httpAddr, "-socks", socksAddr}, io.Discard, io.Discard)

		p, err := url.Parse("http://" + httpAddr)
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			rs, err := client(p).Get(backend.URL)
			if err != nil {
				return false
			}
			_ = rs.Body.Close()
			return rs.StatusCode == http.StatusOK
		}, 5*time.Second, 50*time.Millisecond)
		require.Equal(t, byte(0), socksConnect(t, socksAddr, strings.TrimPrefix(backend.URL, "http://")))
	})
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestNewLogHandlers(t *testing.T) {
	var stdout, stderr bytes.Buffer
	accessHandler, serverHandler := newLogHandlers(&stdout, &stderr)
	access, server := slog.New(accessHandler), slog.New(serverHandler)
	access.Info("", "url", "http://example.com/")
	server.Warn("something", "error", "boom")

	var a, s map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &a))
	require.NoError(t, json.Unmarshal(stderr.Bytes(), &s))
	require.Equal(t, "http://example.com/", a["url"])
	require.NotContains(t, a, "level")
	require.NotContains(t, a, "msg")
	require.Equal(t, "WARN", s["level"])
	require.Equal(t, "something", s["msg"])
}
