package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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

	// KeyAlgorithm selects the algorithm of issued certificate keys: x509.RSA, or x509.ECDSA for P-256.
	// Issue fails on any other value.
	//
	// If 0, x509.RSA will be used.
	KeyAlgorithm x509.PublicKeyAlgorithm

	// BitSize defines bit size for issued RSA keys.
	//
	// If 0, DefaultIssuerBitSize will be used.
	BitSize int

	// Validity is how long an issued certificate stays valid.
	//
	// If 0, DefaultIssuerValidity will be used.
	Validity time.Duration

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

	key, err := ca.generateKey()
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(ca.Rand, serialLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := *ca.Tmpl
	tmpl.SerialNumber = serial
	tmpl.Subject.CommonName = cn
	tmpl.NotBefore = now.Add(-clockSkew)
	tmpl.NotAfter = now.Add(ca.Validity)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	tmpl.DNSNames = dnsnames
	tmpl.IPAddresses = ipaddresses

	der, err := x509.CreateCertificate(ca.Rand, &tmpl, ca.Cert.Leaf, key.Public(), ca.Cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func (ca *SelfSignedCA) generateKey() (crypto.Signer, error) {
	switch ca.KeyAlgorithm {
	case x509.RSA:
		return rsa.GenerateKey(ca.Rand, ca.BitSize)
	case x509.ECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), ca.Rand)
	default:
		return nil, fmt.Errorf("issuer: unsupported key algorithm %s", ca.KeyAlgorithm)
	}
}

// serialLimit bounds serial numbers to the 20 octets RFC 5280 allows.
var serialLimit = new(big.Int).Lsh(big.NewInt(1), 159)

// clockSkew backdates NotBefore so that a client whose clock runs slightly behind accepts a fresh certificate.
const clockSkew = time.Hour

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
	if ca.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		ca.KeyAlgorithm = x509.RSA
	}
	if ca.BitSize == 0 {
		ca.BitSize = DefaultIssuerBitSize
	}
	if ca.Validity == 0 {
		ca.Validity = DefaultIssuerValidity
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

// DefaultIssuerBitSize defines default bit size for issued RSA keys.
const DefaultIssuerBitSize = 2048

// DefaultIssuerValidity is the default validity of issued certificates.
const DefaultIssuerValidity = 30 * 24 * time.Hour

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
