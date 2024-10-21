package x509

import (
	"crypto/x509"
	"time"
)

// Configuration - contains the basic fields required for creating a certificate
type Configuration struct {
	CommonName   string
	Organization []string
	AltNames     AlternativeNames
	Usages       []x509.ExtKeyUsage
	NotBefore    time.Time
}

// AlternativeNames - alternative names contains the domain names and IP addresses
// of the API servers X509 certificate Subject Alternative Name field. The values
// are passed directly to the X509.Certificate object.
type AlternativeNames struct {
	DNSNames []string
	IPs      []string
}
