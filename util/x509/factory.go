package x509

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"time"
)

// NewSelfSignedCACertificate - creates a new self-signed certificate authority certificate
func NewSelfSignedCACertificate(config Configuration, key crypto.Signer) (*x509.Certificate, error) {
	template, err := MakeX509Template(config)
	if err != nil {
		return nil, err
	}

	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// MakeX509Template - returns a new x509.Certificate in a standard configuration
func MakeX509Template(config Configuration) (*x509.Certificate, error) {
	// Timestamps
	//
	now := time.Now()
	notBefore := now.UTC()

	// Create random serial number for the certificate.
	//
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return nil, err
	}
	serial = new(big.Int).Add(serial, big.NewInt(1))

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: config.Organization,
		},
		DNSNames:              []string{config.CommonName},
		NotBefore:             config.NotBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil
}
