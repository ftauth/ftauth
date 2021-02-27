package jwt

// Algorithm is the specific algorithm with which to encode the JWT.
type Algorithm string

// Valid Algorithm values as defined by RFC 7518
const (
	AlgorithmHMACSHA256  Algorithm = "HS256" // required, HMAC using SHA-256
	AlgorithmHMACSHA384  Algorithm = "HS384" // optional, HMAC using SHA-384
	AlgorithmHMACSHA512  Algorithm = "HS512" // optional, HMAC using SHA-512
	AlgorithmRSASHA256   Algorithm = "RS256" // recommended, RRSASSA-PKCS1-v1_5 using SHA-256
	AlgorithmRSASHA384   Algorithm = "RS384" // optional, RRSASSA-PKCS1-v1_5 using SHA-384
	AlgorithmRSASHA512   Algorithm = "RS512" // optional, RRSASSA-PKCS1-v1_5 using SHA-512
	AlgorithmECDSASHA256 Algorithm = "ES256" // recommended+, ECDSA using P-256 and SHA-256
	AlgorithmECDSASHA384 Algorithm = "ES384" // optional, ECDSA using P-384 and SHA-384
	AlgorithmECDSASHA512 Algorithm = "ES512" // optional, ECDSA using P-512 and SHA-512
	AlgorithmPSSSHA256   Algorithm = "PS256" // optional, RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	AlgorithmPSSSHA384   Algorithm = "PS384" // optional, RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	AlgorithmPSSSHA512   Algorithm = "PS512" // optional, RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	AlgorithmNone        Algorithm = "none"  // optional, No digital signature or MAC performed
)

// IsValid returns true if the algorithm is supported
func (alg Algorithm) IsValid() error {
	if alg == "" {
		return errMissingParameter("alg")
	}
	switch alg {
	case AlgorithmHMACSHA256,
		AlgorithmHMACSHA384,
		AlgorithmHMACSHA512,
		AlgorithmRSASHA256,
		AlgorithmRSASHA384,
		AlgorithmRSASHA512,
		AlgorithmECDSASHA256,
		AlgorithmECDSASHA384,
		AlgorithmECDSASHA512,
		AlgorithmPSSSHA256,
		AlgorithmPSSSHA384,
		AlgorithmPSSSHA512:
		return nil
	case AlgorithmNone:
		fallthrough
	default:
		return errUnsupportedValue("alg", string(alg))
	}
}

// ValidForKeyType returns true if the algorithm and key type can be used together.
func (alg Algorithm) ValidForKeyType(kt KeyType) bool {
	switch kt {
	case KeyTypeRSA:
		switch alg {
		case AlgorithmRSASHA256,
			AlgorithmRSASHA384,
			AlgorithmRSASHA512,
			AlgorithmPSSSHA256,
			AlgorithmPSSSHA384,
			AlgorithmPSSSHA512:
			return true
		}
	case KeyTypeEllipticCurve:
		switch alg {
		case AlgorithmECDSASHA256,
			AlgorithmECDSASHA384,
			AlgorithmECDSASHA512:
			return true
		}
	case KeyTypeOctet:
		switch alg {
		case AlgorithmHMACSHA256,
			AlgorithmHMACSHA384,
			AlgorithmHMACSHA512:
			return true
		}
	}
	return false
}

// IsSymmetric returns true for symmetric key-based algorithms.
func (alg Algorithm) IsSymmetric() bool {
	switch alg {
	case AlgorithmHMACSHA256,
		AlgorithmHMACSHA384,
		AlgorithmHMACSHA512:
		return true
	default:
		return false
	}
}
