package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/dnys1/ftoauth/util/base64url"
	"github.com/dnys1/ftoauth/util/base64urluint"
)

type bigInt big.Int

func (bi *bigInt) MarshalJSON() ([]byte, error) {
	_bi := (*big.Int)(bi)
	s := base64urluint.Encode(_bi)
	return json.Marshal(s)
}

func (bi *bigInt) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	_bi, err := base64urluint.Decode(s)
	if _bi == nil || err != nil {
		return err
	}
	*bi = bigInt(*_bi)
	return nil
}

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
	X     *bigInt       `json:"x,omitempty"`   // required, the base64url-encoded x-coordinate
	Y     *bigInt       `json:"y,omitempty"`   // required, the base64url-encoded y-coordinate

	// RSA Properties
	// For KeyTypeRSA (kty = "RSA")

	N *bigInt `json:"n,omitempty"` // required, the base64urlUint-encoded modulus
	E *bigInt `json:"e,omitempty"` // required, the base64urlUint-encoded exponent

	// Symmetric Key Properties
	// For KeyTypeOctet (kty = "octet")

	K string `json:"k,omitempty"` // required, the base64url-encoded key value

	// PrivateKey Properties

	D           *bigInt      `json:"d,omitempty"`   // required for EC/RSA, the base64url-encoded ECC private key or base64urlUint private exponent for RSA
	P           *bigInt      `json:"p,omitempty"`   // required for RSA, the base64urlUint-encoded first prime factor
	Q           *bigInt      `json:"q,omitempty"`   // required for RSA, the base64urlUint-encoded second prime factor
	DP          *bigInt      `json:"dp,omitempty"`  // required for RSA, the base64urlUint-encoded first factor CRT exponent
	DQ          *bigInt      `json:"dq,omitempty"`  // required for RSA, the base64urlUint-encoded second factor CRT exponent
	QI          *bigInt      `json:"qi,omitempty"`  // required for RSA, the base64urlUint-encoded first CRT certificate
	OtherPrimes []OtherPrime `json:"oth,omitempty"` // optional for RSA, the base64urlUint-encoded other primes info
}

// OtherPrime is an extra prime for RSA when more than two primes are needed
type OtherPrime struct {
	R *bigInt `json:"r"` // required, the base64urlUint-encoded prime factor
	D *bigInt `json:"d"` // required, the base64urlUint-encoded factor CRT exponent
	T *bigInt `json:"t"` // required, the base64urlUint-encoded factor CRT coefficient
}

// IsValid returns an error if there are problems with the object.
func (oth OtherPrime) IsValid() error {
	if oth.R == nil {
		return errMissingParameter("r")
	}
	if oth.D == nil {
		return errMissingParameter("d")
	}
	if oth.T == nil {
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
	EllipticCurveP521 EllipticCurve = "P-521"
)

// IsValid returns true if the curve is supported
func (crv EllipticCurve) IsValid() bool {
	switch crv {
	case EllipticCurveP256,
		EllipticCurveP384,
		EllipticCurveP521:
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
		if key.D == nil {
			return errMissingParameter("d")
		}
		if key.P == nil {
			return errMissingParameter("p")
		}
		if key.Q == nil {
			return errMissingParameter("q")
		}
		if key.DP == nil {
			return errMissingParameter("dp")
		}
		if key.DQ == nil {
			return errMissingParameter("dq")
		}
		if key.QI == nil {
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
		if key.D == nil {
			return errMissingParameter("d")
		}
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
		pub := rsa.PublicKey{
			N: (*big.Int)(key.N),
			E: int((*big.Int)(key.E).Int64()),
		}
		key.PublicKey = &pub
		if key.HasPrivateKeyInfo() == nil {
			primes := []*big.Int{(*big.Int)(key.P), (*big.Int)(key.Q)}
			precomp := rsa.PrecomputedValues{
				Dp:   (*big.Int)(key.DP),
				Dq:   (*big.Int)(key.DQ),
				Qinv: (*big.Int)(key.QI),
			}
			if len(key.OtherPrimes) > 0 {
				extraCRT := make([]rsa.CRTValue, 0)
				for _, prime := range key.OtherPrimes {
					primes = append(primes, (*big.Int)(prime.R))
					extraCRT = append(extraCRT, rsa.CRTValue{
						Exp:   (*big.Int)(prime.D),
						Coeff: (*big.Int)(prime.T),
						R:     (*big.Int)(prime.R),
					})
				}
				precomp.CRTValues = extraCRT
			}
			key.PrivateKey = &rsa.PrivateKey{
				PublicKey:   pub,
				D:           (*big.Int)(key.D),
				Primes:      primes,
				Precomputed: precomp,
			}
		}
	case KeyTypeEllipticCurve:
		var curve elliptic.Curve
		switch key.Curve {
		case EllipticCurveP256:
			curve = elliptic.P256()
		case EllipticCurveP384:
			curve = elliptic.P384()
		case EllipticCurveP521:
			curve = elliptic.P521()
		}
		pub := ecdsa.PublicKey{
			Curve: curve,
			X:     (*big.Int)(key.X),
			Y:     (*big.Int)(key.Y),
		}
		key.PublicKey = &pub
		if key.HasPrivateKeyInfo() == nil {
			priv := &ecdsa.PrivateKey{
				PublicKey: pub,
				D:         (*big.Int)(key.D),
			}
			key.PrivateKey = priv
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

	if key.Algorithm == "" {
		err = key.tryParseAlgorithm()
		if err != nil {
			return nil, err
		}
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

func (key *Key) tryParseAlgorithm() error {
	switch key.KeyType {
	case KeyTypeEllipticCurve:
		switch key.Curve {
		case EllipticCurveP256:
			key.Algorithm = AlgorithmECDSASHA256
		case EllipticCurveP384:
			key.Algorithm = AlgorithmECDSASHA384
		case EllipticCurveP521:
			key.Algorithm = AlgorithmECDSASHA512
		}
	case KeyTypeRSA:
	case KeyTypeOctet:
		key.Algorithm = AlgorithmHMACSHA256 // Default symmetric key algo
	}

	if key.Algorithm == "" {
		return errMissingParameter("alg")
	}

	return nil
}

// NewJWKFromRSAPrivateKey creates a JWK from an RSA private key.
func NewJWKFromRSAPrivateKey(key *rsa.PrivateKey) (*Key, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	oth := make([]OtherPrime, 0)
	if len(key.Primes) > 2 && len(key.Precomputed.CRTValues) > 0 {
		for _, crt := range key.Precomputed.CRTValues {
			oth = append(oth, OtherPrime{
				R: (*bigInt)(crt.R),
				D: (*bigInt)(crt.Exp),
				T: (*bigInt)(crt.Coeff),
			})
		}
	}
	e := &big.Int{}
	e.SetInt64(int64(key.E))
	newKey := &Key{
		PublicKey:   &key.PublicKey,
		PrivateKey:  key,
		KeyType:     KeyTypeRSA,
		Algorithm:   AlgorithmRSASHA256,
		N:           (*bigInt)(key.N),
		E:           (*bigInt)(e),
		D:           (*bigInt)(key.D),
		P:           (*bigInt)(key.Primes[0]),
		Q:           (*bigInt)(key.Primes[1]),
		DP:          (*bigInt)(key.Precomputed.Dp),
		DQ:          (*bigInt)(key.Precomputed.Dq),
		QI:          (*bigInt)(key.Precomputed.Qinv),
		OtherPrimes: oth,
	}
	return newKey, newKey.IsValid()
}

// NewJWKFromRSAPublicKey creates a JWK from an RSA public key.
func NewJWKFromRSAPublicKey(key *rsa.PublicKey) (*Key, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	e := &big.Int{}
	e.SetInt64(int64(key.E))
	newKey := &Key{
		PublicKey: key,
		KeyType:   KeyTypeRSA,
		Algorithm: AlgorithmRSASHA256,
		N:         (*bigInt)(key.N),
		E:         (*bigInt)(e),
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
	if key.X == nil {
		return errMissingParameter("x")
	}
	if key.Y == nil {
		return errMissingParameter("y")
	}
	return nil
}

func (key *Key) isValidRSA() error {
	if key.N == nil {
		return errMissingParameter("n")
	}
	if key.E == nil {
		return errMissingParameter("e")
	}
	isPrivateKey := key.PrivateKey != nil
	if isPrivateKey {
		if key.D == nil {
			return errMissingParameter("d")
		}
		if key.P == nil {
			return errMissingParameter("p")
		}
		if key.Q == nil {
			return errMissingParameter("q")
		}
		if key.DP == nil {
			return errMissingParameter("dp")
		}
		if key.DQ == nil {
			return errMissingParameter("dq")
		}
		if key.QI == nil {
			return errMissingParameter("qi")
		}
		if len(key.OtherPrimes) > 0 {
			for i, oth := range key.OtherPrimes {
				if oth.D == nil {
					return errMissingParameter(fmt.Sprintf("oth[%d]: d", i))
				}
				if oth.R == nil {
					return errMissingParameter(fmt.Sprintf("oth[%d]: r", i))
				}
				if oth.T == nil {
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

// Signer is a function for cryptographically signing tokens.
type Signer func(b []byte) ([]byte, error)

// Signer returns a signing function based off the algorithm and private key.
func (key *Key) Signer() Signer {
	switch key.Algorithm {
	case AlgorithmHMACSHA256:
		return key.createHMACSigner(crypto.SHA256)
	case AlgorithmHMACSHA384:
		return key.createHMACSigner(crypto.SHA384)
	case AlgorithmHMACSHA512:
		return key.createHMACSigner(crypto.SHA512)
	case AlgorithmRSASHA256:
		return key.createRSASigner(crypto.SHA256)
	case AlgorithmRSASHA384:
		return key.createRSASigner(crypto.SHA384)
	case AlgorithmRSASHA512:
		return key.createRSASigner(crypto.SHA512)
	case AlgorithmPSSSHA256:
		return key.createPSSSigner(crypto.SHA256)
	case AlgorithmPSSSHA384:
		return key.createPSSSigner(crypto.SHA384)
	case AlgorithmPSSSHA512:
		return key.createPSSSigner(crypto.SHA512)
	case AlgorithmECDSASHA256:
		return key.createECDSASigner(crypto.SHA256)
	case AlgorithmECDSASHA384:
		return key.createECDSASigner(crypto.SHA384)
	case AlgorithmECDSASHA512:
		return key.createECDSASigner(crypto.SHA512)
	}
	return func(b []byte) ([]byte, error) {
		return nil, errUnsupportedValue("alg", string(key.Algorithm))
	}
}

func (key *Key) createHMACSigner(hash crypto.Hash) Signer {
	return func(b []byte) ([]byte, error) {
		mac := hmac.New(hash.New, key.SymmetricKey)
		_, err := mac.Write(b)
		if err != nil {
			return nil, err
		}
		return mac.Sum(nil), nil
	}
}

func (key *Key) createRSASigner(hash crypto.Hash) Signer {
	return func(b []byte) ([]byte, error) {
		if key.PrivateKey == nil {
			return nil, ErrMissingPrivateKey
		}
		rng := rand.Reader
		priv := key.PrivateKey.(*rsa.PrivateKey)
		hasher := hash.New()
		hasher.Write(b)
		hashed := hasher.Sum(nil)
		return rsa.SignPKCS1v15(rng, priv, hash, hashed)
	}
}

func (key *Key) createPSSSigner(hash crypto.Hash) Signer {
	return func(b []byte) ([]byte, error) {
		if key.PrivateKey == nil {
			return nil, ErrMissingPrivateKey
		}
		rng := rand.Reader
		privateKey := key.PrivateKey.(*rsa.PrivateKey)
		hasher := hash.New()
		hasher.Write(b)
		hashed := hasher.Sum(nil)
		return rsa.SignPSS(rng, privateKey, hash, hashed[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	}
}

func (key *Key) createECDSASigner(hash crypto.Hash) Signer {
	var octets int
	switch hash {
	case crypto.SHA256:
		octets = 32
	case crypto.SHA384:
		octets = 48
	case crypto.SHA512:
		octets = 66
	}
	return func(b []byte) ([]byte, error) {
		if key.PrivateKey == nil {
			return nil, ErrMissingPrivateKey
		}
		rnd := rand.Reader
		privateKey := key.PrivateKey.(*ecdsa.PrivateKey)
		hasher := hash.New()
		hasher.Write(b)
		hashed := hasher.Sum(nil)
		r, s, err := ecdsa.Sign(rnd, privateKey, hashed)
		if err != nil {
			return nil, err
		}

		rb := r.Bytes()
		sb := s.Bytes()

		var buf []byte
		// Pad with 0 bytes that r.Bytes removes
		for i := 0; i < octets-len(rb); i++ {
			buf = append(buf, 0)
		}
		buf = append(buf, rb...)

		// Pad with 0 bytes that s.Bytes removes
		for i := 0; i < octets-len(sb); i++ {
			buf = append(buf, 0)
		}
		buf = append(buf, sb...)
		return buf, nil
	}
}

// Verifier is a function for verifying a signature against a public key.
type Verifier func(msg, sig []byte) error

// Verifier returns a function for verifying a signature against the public key.
func (key *Key) Verifier() Verifier {
	switch key.Algorithm {
	case AlgorithmHMACSHA256:
		return key.createHMACVerifier(crypto.SHA256)
	case AlgorithmHMACSHA384:
		return key.createHMACVerifier(crypto.SHA384)
	case AlgorithmHMACSHA512:
		return key.createHMACVerifier(crypto.SHA512)
	case AlgorithmRSASHA256:
		return key.createRSAVerifier(crypto.SHA256)
	case AlgorithmRSASHA384:
		return key.createRSAVerifier(crypto.SHA384)
	case AlgorithmRSASHA512:
		return key.createRSAVerifier(crypto.SHA512)
	case AlgorithmPSSSHA256:
		return key.createPSSVerifier(crypto.SHA256)
	case AlgorithmPSSSHA384:
		return key.createPSSVerifier(crypto.SHA384)
	case AlgorithmPSSSHA512:
		return key.createPSSVerifier(crypto.SHA512)
	case AlgorithmECDSASHA256:
		return key.createECDSAVerifier(crypto.SHA256)
	case AlgorithmECDSASHA384:
		return key.createECDSAVerifier(crypto.SHA384)
	case AlgorithmECDSASHA512:
		return key.createECDSAVerifier(crypto.SHA512)
	}
	return func(msg []byte, sig []byte) error {
		return errUnsupportedValue("alg", string(key.Algorithm))
	}
}

func (key *Key) createHMACVerifier(hash crypto.Hash) Verifier {
	return func(msg, sig []byte) error {
		if key.SymmetricKey == nil {
			return ErrMissingSymmetricKey
		}
		mac := hmac.New(hash.New, key.SymmetricKey)
		_, err := mac.Write(msg)
		if err != nil {
			return err
		}
		if !bytes.Equal(sig, mac.Sum(nil)) {
			return ErrInvalidSignature
		}
		return nil
	}
}

func (key *Key) createRSAVerifier(hash crypto.Hash) Verifier {
	return func(msg, sig []byte) error {
		if key.PublicKey == nil {
			return ErrMissingPublicKey
		}
		publicKey := key.PublicKey.(*rsa.PublicKey)
		hasher := hash.New()
		_, err := hasher.Write(msg)
		if err != nil {
			return err
		}
		hashed := hasher.Sum(nil)
		return rsa.VerifyPKCS1v15(publicKey, hash, hashed, sig)
	}
}

func (key *Key) createPSSVerifier(hash crypto.Hash) Verifier {
	return func(msg, sig []byte) error {
		if key.PublicKey == nil {
			return ErrMissingPublicKey
		}
		publicKey := key.PublicKey.(*rsa.PublicKey)
		hasher := hash.New()
		_, err := hasher.Write(msg)
		if err != nil {
			return err
		}
		hashed := hasher.Sum(nil)
		return rsa.VerifyPSS(publicKey, hash, hashed, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	}
}

func (key *Key) createECDSAVerifier(hash crypto.Hash) Verifier {
	var expectedOctets int
	switch hash {
	case crypto.SHA256:
		expectedOctets = 32
	case crypto.SHA384:
		expectedOctets = 48
	case crypto.SHA512:
		expectedOctets = 66
	}
	return func(msg, sig []byte) error {
		if key.PublicKey == nil {
			return ErrMissingPublicKey
		}

		octets := len(sig)
		if octets != expectedOctets*2 {
			return ErrInvalidSignature
		}
		half := expectedOctets

		r := &big.Int{}
		r = r.SetBytes(sig[:half])

		s := &big.Int{}
		s = s.SetBytes(sig[half:])

		pub := key.PublicKey.(*ecdsa.PublicKey)
		hasher := hash.New()
		hasher.Write(msg)
		hashed := hasher.Sum(nil)

		if !ecdsa.Verify(pub, hashed, r, s) {
			return ErrInvalidSignature
		}
		return nil
	}
}

// Thumbprint returns the SHA-256 thumbprint of the key.
func (key *Key) Thumbprint() (string, error) {
	// Fields used in computation per RFC7638
	var s interface{}
	switch key.KeyType {
	case KeyTypeRSA:
		s = struct {
			E       *bigInt `json:"e"`
			KeyType KeyType `json:"kty"`
			N       *bigInt `json:"n"`
		}{
			E:       key.E,
			KeyType: key.KeyType,
			N:       key.N,
		}
	case KeyTypeEllipticCurve:
		s = struct {
			Curve   EllipticCurve `json:"crv"`
			KeyType KeyType       `json:"kty"`
			X       *bigInt       `json:"x"`
			Y       *bigInt       `json:"y"`
		}{
			Curve:   key.Curve,
			KeyType: key.KeyType,
			X:       key.X,
			Y:       key.Y,
		}
	case KeyTypeOctet:
		s = struct {
			K       string  `json:"k"`
			KeyType KeyType `json:"kty"`
		}{
			K:       key.K,
			KeyType: key.KeyType,
		}
	}

	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(b)

	return base64url.Encode(digest[:]), nil
}
