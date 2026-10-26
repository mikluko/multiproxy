package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// RootTemplate returns a template for a CA certificate with the given subject, valid for validity from now.
func RootTemplate(commonName, organization string, validity time.Duration) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
}

// NewRoot creates a self-signed certificate from tmpl with a fresh RSA key of bits size. The serial number is
// random, whatever tmpl carries.
func NewRoot(tmpl *x509.Certificate, bits int, rnd io.Reader) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rnd, bits)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rnd, serialLimit)
	if err != nil {
		return nil, err
	}
	t := *tmpl
	t.SerialNumber = serial
	der, err := x509.CreateCertificate(rnd, &t, &t, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// LoadOrCreate reads a CA certificate and its key from PEM files. Where neither file exists, it creates a root
// from tmpl and writes both. One file without the other, or a certificate that is not a CA, is an error.
func LoadOrCreate(certFile, keyFile string, tmpl *x509.Certificate) (*tls.Certificate, error) {
	certExists, err := exists(certFile)
	if err != nil {
		return nil, err
	}
	keyExists, err := exists(keyFile)
	if err != nil {
		return nil, err
	}
	switch {
	case certExists && keyExists:
		return load(certFile, keyFile)
	case certExists:
		return nil, fmt.Errorf("issuer: %s exists but %s does not", certFile, keyFile)
	case keyExists:
		return nil, fmt.Errorf("issuer: %s exists but %s does not", keyFile, certFile)
	}
	if !tmpl.IsCA {
		return nil, errors.New("issuer: template is not a CA")
	}
	cert, err := NewRoot(tmpl, DefaultIssuerRootBitSize, rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := WriteFiles(cert, certFile, keyFile); err != nil {
		return nil, err
	}
	return cert, nil
}

// WriteFiles writes cert as PEM to certFile, and its private key as PKCS #8 PEM to keyFile with mode 0600.
// Neither file may exist already.
func WriteFiles(cert *tls.Certificate, certFile, keyFile string) error {
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	if err := writeNew(keyFile, 0o600, &pem.Block{Type: "PRIVATE KEY", Bytes: key}); err != nil {
		return err
	}
	return writeNew(certFile, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func load(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	if !cert.Leaf.IsCA {
		return nil, fmt.Errorf("issuer: %s is not a CA", certFile)
	}
	return &cert, nil
}

func writeNew(name string, perm fs.FileMode, block *pem.Block) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func exists(name string) (bool, error) {
	_, err := os.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
