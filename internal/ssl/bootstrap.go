package ssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	defaultRsaBits    int            = 2048
	defaultEcdsaCurve elliptic.Curve = elliptic.P256()
	defaultValidFor   time.Duration  = 365 * 24 * time.Hour
)

// publicKey returns the public key for the given private key. RSA, ECDSA, and Ed25519 keys
// are supported.
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// GenerateKey creates a public/private key pair for the given algorithm and parameters.
// RSA, ECDSA, and Ed25519 keys are supported.
func GenerateKey(
	keyType x509.PublicKeyAlgorithm,
	rsaBits *int,
	ecdsaCurve *elliptic.Curve,
) (priv interface{}, err error) {
	switch keyType {
	case x509.ECDSA:
		if ecdsaCurve == nil {
			ecdsaCurve = &defaultEcdsaCurve
		}
		priv, err = ecdsa.GenerateKey(*ecdsaCurve, rand.Reader)
	case x509.RSA:
		if rsaBits == nil {
			rsaBits = &defaultRsaBits
		}
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	case x509.Ed25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	}
	return
}

// GenerateCertificate creates a self-signed certificate for the given comma-separated
// list of hosts and returns the certificate PEM bytes and the PKCS8 private key
// PEM bytes.
//
// RSA, ECDSA, and Ed25519 keys are supported.
func GenerateCertificate(
	host string,
	subject pkix.Name,
	priv interface{},
	validFrom *time.Time,
	validFor *time.Duration,
	isCA bool,
) ([]byte, []byte, error) {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if validFrom == nil {
		notBefore = time.Now()
	} else {
		notBefore = *validFrom
	}

	if validFor == nil {
		validFor = &defaultValidFor
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certOut, keyOut := new(bytes.Buffer), new(bytes.Buffer)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to cert.pem: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to key.pem: %v", err)
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
}
