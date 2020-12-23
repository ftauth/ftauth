package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dnys1/ftoauth/util/base64url"
	"github.com/dnys1/ftoauth/util/base64urluint"
)

// Key is a JSON Web Key which holds cryptographic information
// about the signing/encryption used for a JSON Web Token.
type Key struct {
	// The keys. One or multiple of these must be present.
	// For symmetric keys, only SymmetricKey should be present
	// For RSA/EC keys, at least PublicKey must be present
	// These keys are created during parsing if creating
	// a key from a JSON Web Key (JWK)

	SymmetricKey []byte            `json:"-"` // required, the symmetric key bytes
	PublicKey    crypto.PublicKey  `json:"-"` // required for RSA/EC, the public key
	PrivateKey   crypto.PrivateKey `json:"-"` // optional for RSA/EC, the private key

	// Key details

	KeyType               KeyType        `json:"kty,omitempty"`      // required, the cryptographic algorithm family used with the key
	PublicKeyUse          PublicKeyUse   `json:"use,omitempty"`      // optional, the intended use of the public key
	KeyOperations         []KeyOperation `json:"key_ops,omitempty"`  // optional, list of operations this key is intended to perform
	Algorithm             Algorithm      `json:"alg,omitempty"`      // optional, algorithm intended for use with this key
	KeyID                 string         `json:"kid,omitempty"`      // optional, used to match "kid" value in JWT header
	X509Url               string         `json:"x5u,omitempty"`      // optional, URL of X.509 certificate
	X509CertificateChain  []string       `json:"x5c,omitempty"`      // optional, base64-encoded PKIX certificates (1+)
	X509CertificateSHA1   string         `json:"x5t,omitempty"`      // optional, base64url-encoded SHA-1 fingerprint of X.509
	X509CertificateSHA256 string         `json:"x5t#S256,omitempty"` // optional, base64url-encoded SHA-256 fingerprint of X.509

	// Elliptic Curve Properties
	// For KeyTypeEllipticCurve (kty = "EC")

	Curve EllipticCurve `json:"crv,omitempty"` // required, the elliptic curve for the public key
	X     string        `json:"x,omitempty"`   // required, the base64url-encoded x-coordinate
	Y     string        `json:"y,omitempty"`   // required, the base64url-encoded y-coordinate

	// RSA Properties
	// For KeyTypeRSA (kty = "RSA")

	N string `json:"n,omitempty"` // required, the base64urlUint-encoded modulus
	E string `json:"e,omitempty"` // required, the base64urlUint-encoded exponent

	// Symmetric Key Properties
	// For KeyTypeOctet (kty = "octet")

	K string `json:"k,omitempty"` // required, the base64url-encoded key value

	// PrivateKey Properties

	D           string       `json:"d,omitempty"`   // required for EC/RSA, the base64url-encoded ECC private key or base64urlUint private exponent for RSA
	P           string       `json:"p,omitempty"`   // required for RSA, the base64urlUint-encoded first prime factor
	Q           string       `json:"q,omitempty"`   // required for RSA, the base64urlUint-encoded second prime factor
	DP          string       `json:"dp,omitempty"`  // required for RSA, the base64urlUint-encoded first factor CRT exponent
	DQ          string       `json:"dq,omitempty"`  // required for RSA, the base64urlUint-encoded second factor CRT exponent
	QI          string       `json:"qi,omitempty"`  // required for RSA, the base64urlUint-encoded first CRT certificate
	OtherPrimes []OtherPrime `json:"oth,omitempty"` // optional for RSA, the base64urlUint-encoded other primes info
}

// OtherPrime is an extra prime for RSA when more than two primes are needed
type OtherPrime struct {
	R string `json:"r"` // required, the base64urlUint-encoded prime factor
	D string `json:"d"` // required, the base64urlUint-encoded factor CRT exponent
	T string `json:"t"` // required, the base64urlUint-encoded factor CRT coefficient
}

// IsValid returns an error if there are problems with the object.
func (oth OtherPrime) IsValid() error {
	if oth.R == "" {
		return errMissingParameter("r")
	}
	if oth.D == "" {
		return errMissingParameter("d")
	}
	if oth.T == "" {
		return errMissingParameter("t")
	}
	return nil
}

// KeyType is the cryptographic algorithm family used with the key.
type KeyType string

// Valid values for KeyType per RFC 7518
const (
	KeyTypeEllipticCurve KeyType = "EC"  // recommended+
	KeyTypeRSA           KeyType = "RSA" // required
	KeyTypeOctet         KeyType = "oct" // required
)

// IsValid returns true if the key type is supported
func (typ KeyType) IsValid() bool {
	switch typ {
	case KeyTypeEllipticCurve,
		KeyTypeRSA,
		KeyTypeOctet:
		return true
	}
	return false
}

// PublicKeyUse defines the intended use of the public key.
type PublicKeyUse string

// Allowed values for PublicKeyUse as defined by RFC 7517
const (
	PublicKeyUseSignature  PublicKeyUse = "sig"
	PublicKeyUseEncryption PublicKeyUse = "enc"
)

// IsValid checks whether the given use is valid.
func (use PublicKeyUse) IsValid() error {
	switch use {
	case PublicKeyUseSignature,
		PublicKeyUseEncryption:
		return nil
	}
	return errUnsupportedValue("use", string(use))
}

// KeyOperation specifies the operation(s) for which the key
// is intended to be used.
type KeyOperation string

// Allowed values for KeyOperation as defined by RFC 7517
const (
	KeyOperationSign        KeyOperation = "sign"
	KeyOperationVerify      KeyOperation = "verify"
	KeyOperationEncrypt     KeyOperation = "encrypt"
	KeyOperationDecrypt     KeyOperation = "decrypt"
	KeyOperationWrapKey     KeyOperation = "wrapKey"
	KeyOperationUnwrapKey   KeyOperation = "unwrapKey"
	KeyOperationDeriveKey   KeyOperation = "deriveKey"
	KeyOperationDeriveBytes KeyOperation = "deriveBytes"
)

// EllipticCurve is the curve to use for elliptic curve public keys
type EllipticCurve string

// Valid EllipticCurve values per RFC 7518
const (
	EllipticCurveP256 EllipticCurve = "P-256"
	EllipticCurveP384 EllipticCurve = "P-384"
	EllipticCurveP512 EllipticCurve = "P-512"
)

// IsValid returns true if the curve is supported
func (crv EllipticCurve) IsValid() bool {
	switch crv {
	case EllipticCurveP256,
		EllipticCurveP384,
		EllipticCurveP512:
		return true
	}
	return false
}

// HasPrivateKeyInfo validates whether or not private key
// information is included, specific to the algorithm used.
func (key *Key) HasPrivateKeyInfo() error {
	switch key.KeyType {
	case KeyTypeOctet:
		return nil
	case KeyTypeRSA:
		if key.D == "" {
			return errMissingParameter("d")
		}
		if key.P == "" {
			return errMissingParameter("p")
		}
		if key.Q == "" {
			return errMissingParameter("q")
		}
		if key.DP == "" {
			return errMissingParameter("dp")
		}
		if key.DQ == "" {
			return errMissingParameter("dq")
		}
		if key.QI == "" {
			return errMissingParameter("qi")
		}

		if len(key.OtherPrimes) > 0 {
			for i, oth := range key.OtherPrimes {
				err := oth.IsValid()
				if err != nil {
					return fmt.Errorf("Error with oth[%d]: %v", i, err)
				}
			}
		}
	case KeyTypeEllipticCurve:
		// TODO
	}
	return nil
}

// GenerateKey attempts to parse the key encoded in the JWK.
func (key *Key) generateKey() error {
	switch key.KeyType {
	case KeyTypeOctet:
		b, err := base64url.Decode(key.K)
		if err != nil {
			return err
		}
		key.SymmetricKey = b
	case KeyTypeRSA:
		n, err := base64urluint.Decode(key.N)
		if err != nil {
			return err
		}
		e, err := strconv.Atoi(key.E)
		if err != nil {
			return err
		}
		pub := rsa.PublicKey{
			N: n,
			E: e,
		}
		key.PublicKey = pub
		if key.HasPrivateKeyInfo() == nil {
			d, err := base64urluint.Decode(key.D)
			if err != nil {
				return err
			}

			p, err := base64urluint.Decode(key.P)
			if err != nil {
				return err
			}
			q, err := base64urluint.Decode(key.Q)
			if err != nil {
				return err
			}
			dp, err := base64urluint.Decode(key.DP)
			if err != nil {
				return err
			}
			dq, err := base64urluint.Decode(key.DQ)
			if err != nil {
				return err
			}
			qi, err := base64urluint.Decode(key.QI)
			if err != nil {
				return err
			}
			primes := []*big.Int{p, q}
			precomp := rsa.PrecomputedValues{
				Dp:   dp,
				Dq:   dq,
				Qinv: qi,
			}
			if len(key.OtherPrimes) > 0 {
				extraCRT := make([]rsa.CRTValue, 0)
				for i, prime := range key.OtherPrimes {
					r, err := base64urluint.Decode(prime.R)
					if err != nil {
						return fmt.Errorf("Error in oth[%d]: %v", i, err)
					}
					d, err := base64urluint.Decode(prime.D)
					if err != nil {
						return fmt.Errorf("Error in oth[%d]: %v", i, err)
					}
					t, err := base64urluint.Decode(prime.T)
					if err != nil {
						return fmt.Errorf("Error in oth[%d]: %v", i, err)
					}
					primes = append(primes, r)
					extraCRT = append(extraCRT, rsa.CRTValue{
						Exp:   d,
						Coeff: t,
						R:     r,
					})
				}
				precomp.CRTValues = extraCRT
			}
			key.PrivateKey = rsa.PrivateKey{
				PublicKey:   pub,
				D:           d,
				Primes:      primes,
				Precomputed: precomp,
			}
		}
	}
	return nil
}

// ParseJWK converts a JSON Web Key to a Key.
func ParseJWK(jwk string) (*Key, error) {
	var key Key
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return nil, err
	}

	// Set default so we can create Signer
	// Parameter is not required by RFC.
	if key.Algorithm == "" {
		key.Algorithm = AlgorithmHMACSHA256
	}

	err = key.IsValid()
	if err != nil {
		return nil, err
	}

	err = key.generateKey()
	if err != nil {
		return nil, err
	}

	return &key, nil
}

// NewFromRSAPrivateKey creates a JWK from an RSA private key.
func NewFromRSAPrivateKey(key *rsa.PrivateKey) (*Key, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	oth := make([]OtherPrime, 0)
	if len(key.Primes) > 2 && len(key.Precomputed.CRTValues) > 0 {
		for _, crt := range key.Precomputed.CRTValues {
			oth = append(oth, OtherPrime{
				R: crt.R.String(),
				D: crt.Exp.String(),
				T: crt.Coeff.String(),
			})
		}
	}
	newKey := &Key{
		PublicKey:   &key.PublicKey,
		PrivateKey:  key,
		KeyType:     KeyTypeRSA,
		N:           key.N.String(),
		E:           strconv.Itoa(key.E),
		D:           key.D.String(),
		P:           key.Primes[0].String(),
		Q:           key.Primes[1].String(),
		DP:          key.Precomputed.Dp.String(),
		DQ:          key.Precomputed.Dp.String(),
		QI:          key.Precomputed.Qinv.String(),
		OtherPrimes: oth,
	}
	return newKey, newKey.IsValid()
}

// NewFromRSAPublicKey creates a JWK from an RSA public key.
func NewFromRSAPublicKey(key *rsa.PublicKey) (*Key, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	newKey := &Key{
		PublicKey: key,
		KeyType:   KeyTypeRSA,
		N:         key.N.String(),
		E:         strconv.Itoa(key.E),
	}

	return newKey, newKey.IsValid()
}

// IsValid returns true if this JWK has a valid structure and contents
// per the requirements of RFC 7417.
func (key *Key) IsValid() error {
	if key.KeyType == "" {
		return errMissingParameter("kty")
	}
	if !key.KeyType.IsValid() {
		return errInvalidParameter("kty")
	}

	var validator func() error
	switch key.KeyType {
	case KeyTypeEllipticCurve:
		validator = key.isValidEllipticCurve
	case KeyTypeRSA:
		validator = key.isValidRSA
	case KeyTypeOctet:
		validator = key.isValidSymmetric
	}

	err := validator()
	if err != nil {
		return err
	}

	if key.PublicKeyUse != "" {
		err = key.PublicKeyUse.IsValid()
		if err != nil {
			return err
		}
	}

	// KeyOperations array must contain valid values and
	// must not contain duplicate values.
	seen := make(map[KeyOperation]bool)
	for _, keyOp := range key.KeyOperations {
		val := seen[keyOp]
		if val {
			return errDuplicateKey(string(keyOp))
		}
		seen[keyOp] = true
		switch keyOp {
		case KeyOperationSign,
			KeyOperationVerify,
			KeyOperationEncrypt,
			KeyOperationDecrypt,
			KeyOperationWrapKey,
			KeyOperationUnwrapKey,
			KeyOperationDeriveKey,
			KeyOperationDeriveBytes:
			continue
		}
		return errInvalidParameter("key_ops")
	}

	if key.Algorithm != "" {
		err = key.Algorithm.IsValid()
		if err != nil {
			return err
		}
	}

	// If present, check X509 parameters

	return nil
}

func (key *Key) isValidEllipticCurve() error {
	if !key.Curve.IsValid() {
		return errInvalidParameter("crv")
	}

	// TODO (dnys1): Check `d`
	// The length of this octet string MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the curve).
	err := key.HasPrivateKeyInfo()
	if err != nil {
		return err
	}
	if key.X == "" {
		return errMissingParameter("x")
	}
	if key.Y == "" {
		return errMissingParameter("y")
	}
	return nil
}

func (key *Key) isValidRSA() error {
	if key.N == "" {
		return errMissingParameter("n")
	}
	if key.E == "" {
		return errMissingParameter("e")
	}
	isPrivateKey := key.PrivateKey != nil
	if isPrivateKey {
		if key.D == "" {
			return errMissingParameter("d")
		}
		if key.P == "" {
			return errMissingParameter("p")
		}
		if key.Q == "" {
			return errMissingParameter("q")
		}
		if key.DP == "" {
			return errMissingParameter("dp")
		}
		if key.DQ == "" {
			return errMissingParameter("dq")
		}
		if key.QI == "" {
			return errMissingParameter("qi")
		}
		if len(key.OtherPrimes) > 0 {
			for i, oth := range key.OtherPrimes {
				if oth.D == "" {
					return errMissingParameter(fmt.Sprintf("oth[%d]: d", i))
				}
				if oth.R == "" {
					return errMissingParameter(fmt.Sprintf("oth[%d]: r", i))
				}
				if oth.T == "" {
					return errMissingParameter(fmt.Sprintf("oth[%d]: t", i))
				}
			}
		}
	}

	return nil
}

func (key *Key) isValidSymmetric() error {
	if key.K == "" {
		return errMissingParameter("k")
	}
	return nil
}

// RetrieveX509Certificate downloads the key's X.509 certificate as
// specified by the X509Url parameter, if included.
func (key *Key) RetrieveX509Certificate() (cert []byte, err error) {
	if key.X509Url == "" {
		err = errors.New("X.509 URL parameter not present")
		return
	}

	parsedURL, err := url.Parse(key.X509Url)
	if err != nil {
		return
	}
	if parsedURL.Scheme != "https" {
		err = fmt.Errorf("Protocol is not supported for certificate retrieval: %s", parsedURL.Scheme)
		return
	}
	resp, err := http.Get(key.X509Url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Error downloading X.509 certificate from URL: %s", key.X509Url)
		return
	}
	cert, err = ioutil.ReadAll(resp.Body)
	return
}

// Signer returns a signing/hashing function based off
// the algorithm and private key.
func (key *Key) Signer() func([]byte) ([]byte, error) {
	switch key.Algorithm {
	case AlgorithmHMACSHA256:
		return func(b []byte) ([]byte, error) {
			mac := hmac.New(sha256.New, key.SymmetricKey)
			_, err := mac.Write(b)
			if err != nil {
				return nil, err
			}
			return mac.Sum(nil), nil
		}
	case AlgorithmRSASHA256:
		return func(b []byte) ([]byte, error) {
			rng := rand.Reader
			privateKey := key.PrivateKey.(rsa.PrivateKey)
			hashed := sha256.Sum256(b)
			return rsa.SignPSS(rng, &privateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			})
		}
	}
	return func(b []byte) ([]byte, error) {
		return nil, errUnsupportedValue("alg", string(key.Algorithm))
	}
}
