package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
)

func TestParseFlags(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := parseFlags(nil, io.Discard)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1:8080", cfg.listen)
		require.Equal(t, "*", cfg.tunnelHosts)
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
		rs := get(t, proxy(t), backend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.NotEmpty(t, rs.Header.Get("X-Seen-Via"))
	})
	t.Run("plain HTTP without Via", func(t *testing.T) {
		rs := get(t, proxy(t, "-novia"), backend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.Empty(t, rs.Header.Get("X-Seen-Via"))
	})
	t.Run("CONNECT is tunnelled by default", func(t *testing.T) {
		rs := get(t, proxy(t), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.True(t, rs.TLS.PeerCertificates[0].Equal(tlsBackend.Certificate()))
	})
	t.Run("CONNECT to a -mitm host is intercepted", func(t *testing.T) {
		rs := get(t, proxy(t, "-mitm", "127.0.0.1"), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		leaf := rs.TLS.PeerCertificates[0]
		require.Equal(t, issuer.DefaultIssuerRootTmpl.Subject.CommonName, leaf.Issuer.CommonName)
		require.IsType(t, &rsa.PublicKey{}, leaf.PublicKey)
	})
	t.Run("-leaf-key ecdsa", func(t *testing.T) {
		rs := get(t, proxy(t, "-mitm", "127.0.0.1", "-leaf-key", "ecdsa"), tlsBackend.URL)
		require.Equal(t, http.StatusOK, rs.StatusCode)
		require.IsType(t, &ecdsa.PublicKey{}, rs.TLS.PeerCertificates[0].PublicKey)
	})
	t.Run("CONNECT to an unlisted host is refused", func(t *testing.T) {
		p := proxy(t, "-mitm", "example.com")
		_, err := client(p).Get(tlsBackend.URL)
		require.ErrorContains(t, err, "Method Not Allowed")
	})
	t.Run("two fallback handlers", func(t *testing.T) {
		cfg, err := parseFlags([]string{"-mitm", "*", "-tunnel", "*"}, io.Discard)
		require.NoError(t, err)
		_, err = newHandler(cfg, io.Discard, io.Discard)
		require.Error(t, err)
	})
}

// echoVia answers 200 and reports the Via header it received as X-Seen-Via.
func echoVia(rw http.ResponseWriter, rq *http.Request) {
	rw.Header().Set("X-Seen-Via", rq.Header.Get("Via"))
	rw.WriteHeader(http.StatusOK)
}

// proxy starts the proxy configured by args and returns its URL.
func proxy(t *testing.T, args ...string) *url.URL {
	t.Helper()
	cfg, err := parseFlags(append([]string{"-noaccesslog"}, args...), io.Discard)
	require.NoError(t, err)
	h, err := newHandler(cfg, io.Discard, io.Discard)
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
