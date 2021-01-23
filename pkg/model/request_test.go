package model

import "testing"

// TestResponseErrorTypes asserts that all RequestError
// types conform to the RequestError interface.
func TestResponseErrorTypes(t *testing.T) {
	var _ RequestError = AuthorizationRequestError("")
	var _ RequestError = TokenRequestError("")
}
