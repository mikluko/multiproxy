package issuer_test

import (
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sarak.sh/mikluko/multiproxy/pkg/issuer"
)

func TestRootTemplate(t *testing.T) {
	tmpl := issuer.RootTemplate("Test Root", "Test Org", 24*time.Hour)
	require.Equal(t, "Test Root", tmpl.Subject.CommonName)
	require.Equal(t, []string{"Test Org"}, tmpl.Subject.Organization)
	require.True(t, tmpl.IsCA)
	require.True(t, tmpl.BasicConstraintsValid)
	require.NotZero(t, tmpl.KeyUsage&x509.KeyUsageCertSign)
	require.True(t, tmpl.NotBefore.Before(time.Now()))
	require.WithinDuration(t, time.Now().Add(24*time.Hour), tmpl.NotAfter, time.Minute)
}

func TestNewRoot(t *testing.T) {
	tmpl := issuer.RootTemplate("Test Root", "Test Org", 24*time.Hour)
	a, err := issuer.NewRoot(tmpl, 2048, rand.Reader)
	require.NoError(t, err)
	b, err := issuer.NewRoot(tmpl, 2048, rand.Reader)
	require.NoError(t, err)

	require.Equal(t, "Test Root", a.Leaf.Subject.CommonName)
	require.True(t, a.Leaf.IsCA)
	require.Equal(t, x509.SHA256WithRSA, a.Leaf.SignatureAlgorithm)
	require.NotEqual(t, a.Leaf.SerialNumber, b.Leaf.SerialNumber)
	require.NoError(t, a.Leaf.CheckSignatureFrom(a.Leaf))
}

func TestLoadOrCreate(t *testing.T) {
	tmpl := issuer.RootTemplate("Test Root", "Test Org", 24*time.Hour)

	t.Run("creates, then loads the same CA", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")

		created, err := issuer.LoadOrCreate(certFile, keyFile, tmpl)
		require.NoError(t, err)
		require.Equal(t, "Test Root", created.Leaf.Subject.CommonName)

		info, err := os.Stat(keyFile)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		loaded, err := issuer.LoadOrCreate(certFile, keyFile, issuer.RootTemplate("Other", "Other", time.Hour))
		require.NoError(t, err)
		require.True(t, created.Leaf.Equal(loaded.Leaf))

		ca := &issuer.SelfSignedCA{Cert: loaded}
		leaf, err := ca.Issue("example.com", []string{"example.com"}, nil)
		require.NoError(t, err)
		roots := x509.NewCertPool()
		roots.AddCert(created.Leaf)
		_, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots})
		require.NoError(t, err)
	})
	t.Run("one file without the other", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
		require.NoError(t, os.WriteFile(certFile, []byte("x"), 0o644))
		_, err := issuer.LoadOrCreate(certFile, keyFile, tmpl)
		require.ErrorContains(t, err, keyFile)
	})
	t.Run("not PEM", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
		require.NoError(t, os.WriteFile(certFile, []byte("x"), 0o644))
		require.NoError(t, os.WriteFile(keyFile, []byte("x"), 0o600))
		_, err := issuer.LoadOrCreate(certFile, keyFile, tmpl)
		require.Error(t, err)
	})
	t.Run("not a CA", func(t *testing.T) {
		dir := t.TempDir()
		certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
		leafTmpl := *tmpl
		leafTmpl.IsCA = false
		leafTmpl.KeyUsage = x509.KeyUsageDigitalSignature

		_, err := issuer.LoadOrCreate(certFile, keyFile, &leafTmpl)
		require.ErrorContains(t, err, "not a CA")
		require.NoFileExists(t, certFile)

		leaf, err := issuer.NewRoot(&leafTmpl, 2048, rand.Reader)
		require.NoError(t, err)
		require.NoError(t, issuer.WriteFiles(leaf, certFile, keyFile))
		_, err = issuer.LoadOrCreate(certFile, keyFile, tmpl)
		require.ErrorContains(t, err, "not a CA")
	})
}
