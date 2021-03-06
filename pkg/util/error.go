package util

import (
	"errors"
	"fmt"
)

// ErrMissingParameter reports a missing value for a required paramter.
func ErrMissingParameter(name string) error {
	return fmt.Errorf("Missing parameter: %s", name)
}

// ErrInvalidParameter reports an incorrect value for a parameter.
func ErrInvalidParameter(name string) error {
	return fmt.Errorf("Invalid parameter: %s", name)
}

// ErrUnsupportedValue reports an incorrect value for an enum or for
// a variable with a discrete set of options.
func ErrUnsupportedValue(name, value string) error {
	return fmt.Errorf("Unsupported key-value pair %s: %s", name, value)
}

// Token errors
var (
	ErrMustEncodeFirst     = errors.New("must encode token first")
	ErrMissingPrivateKey   = errors.New("missing private key")
	ErrMissingPublicKey    = errors.New("missing public key")
	ErrMissingSymmetricKey = errors.New("missing symmetric key")
)
