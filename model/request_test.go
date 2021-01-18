package model

import "testing"

// Test_ResponseErrorTypes asserts that all RequestError
// types conform to the RequestError interface.
func Test_ResponseErrorTypes(t *testing.T) {
	var _ RequestError = AuthorizationRequestError("")
	var _ RequestError = TokenRequestError("")
}
