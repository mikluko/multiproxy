package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// Issuer defines interface for on-flight certificate generator
type Issuer interface {
	Issue(cn string, dnsnames []string, ipaddresses []net.IP) (*tls.Certificate, error)
}

// SelfSignedCA defines an Issuer. Zero value is a valid instance.
type SelfSignedCA struct {
	// Cert is a cert chain used to sign newly issued certs. The cert's primary usage must be x509.KeyUsageCertSign
	//
	// If nil, a self-signed cert will be generated.
	Cert *tls.Certificate

	// BitSize defines bit size for issued certificate keys generation.
	//
	// If 0, DefaultIssuerBitSize will be used.
	BitSize int

	// RootBitSize defines bit size for self-signed root certificate key generation.
	//
	// If 0, DefaultIssuerRootBitSize will be used.
	RootBitSize int

	// Tmpl is a template for issued certificates.
	//
	// If nil, DefaultIssuerTmpl will be used.
	Tmpl *x509.Certificate

	// RootTmpl is a template for self-signed root certificate.
	//
	// If nil, DefaultIssuerRootTmpl will be used.
	RootTmpl *x509.Certificate

	// Rand is a source of randomness for generated certs.
	//
	// If nil, crypto/rand.Reader will be used.
	Rand io.Reader

	once sync.Once
}

// Issue implements Issuer interface
func (ca *SelfSignedCA) Issue(cn string, dnsnames []string, ipaddresses []net.IP) (*tls.Certificate, error) {
	ca.once.Do(ca.init)

	tmpl := *ca.Tmpl
	tmpl.Subject.CommonName = cn
	tmpl.NotBefore = time.Now()
	tmpl.NotAfter = time.Now().AddDate(10, 0, 0)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	tmpl.DNSNames = dnsnames
	tmpl.IPAddresses = ipaddresses

	key, err := rsa.GenerateKey(ca.Rand, 1024)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(ca.Rand, &tmpl, ca.Cert.Leaf, &key.PublicKey, ca.Cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (ca *SelfSignedCA) init() {
	if ca.Rand == nil {
		ca.Rand = rand.Reader
	}
	if ca.Tmpl == nil {
		ca.Tmpl = &DefaultIssuerTmpl
	}
	if ca.RootTmpl == nil {
		ca.RootTmpl = &DefaultIssuerRootTmpl
	}
	if ca.BitSize == 0 {
		ca.BitSize = DefaultIssuerBitSize
	}
	if ca.RootBitSize == 0 {
		ca.RootBitSize = DefaultIssuerRootBitSize
	}
	if ca.Cert == nil {
		ca.initRootCert()
	}
	if ca.Cert.Leaf == nil {
		// pre-parse leaf certificate, ignore potential error, it will inevitably pop up on the first use any way
		ca.Cert.Leaf, _ = x509.ParseCertificate(ca.Cert.Certificate[0])
	}
}

func (ca *SelfSignedCA) initRootCert() {
	key, err := rsa.GenerateKey(ca.Rand, ca.RootBitSize)
	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(ca.Rand, ca.RootTmpl, ca.RootTmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		panic(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		panic(err)
	}
	ca.Cert = &pair
}

// DefaultIssuerRootBitSize defines default bit size for a self-signed root cert.
const DefaultIssuerRootBitSize = 2048

// DefaultIssuerBitSize defines default bit size for issued certs.
const DefaultIssuerBitSize = 1024

var (
	// DefaultIssuerRootTmpl is the default template for self-signed root CA certificate.
	DefaultIssuerRootTmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer: pkix.Name{
			CommonName:   "issuer.example.org",
			Organization: []string{"Multiproxy Issuer Org"},
		},
		Subject: pkix.Name{
			CommonName:   "root.example.org",
			Organization: []string{"Multiproxy Root Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 2),
		IsCA:                  true,
		BasicConstraintsValid: true,
		OCSPServer:            []string{"ocsp.example.org"},
		DNSNames:              []string{"root.example.org"},
		SignatureAlgorithm:    x509.SHA1WithRSA,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	// DefaultIssuerTmpl is the default template for issued certificates.
	DefaultIssuerTmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"AQ"},
			Organization: []string{"Multiproxy"},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
)
