package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/jwt"
	"github.com/gorilla/mux"
)

// Middleware errors
var (
	ErrEmptyAuthHeader = errors.New("empty auth header")
	ErrEmptyDPoPHeader = errors.New("empty DPoP header")
)

// SuppressReferrer follows best practices to avoid leaking
// the authorization code or state parameter via the Referrer
// header being maliciously targetted.
//
// See Section 4.2.4: https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16
func SuppressReferrer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")

		next.ServeHTTP(w, r)
	})
}

// BearerAuthenticated protects endpoints based off a user's Bearer auth token.
func BearerAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		_, err := decodeAndVerifyAuthHeader(authHeader)
		if err != nil {
			log.Printf("Error decoding/verifying auth header: %v\n", err)
			if errors.Is(err, ErrEmptyAuthHeader) {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// BearerAuthenticatedWithScope protects endpoints based off a user's Bearer auth token
// and the assigned scopes on the bearer token.
func BearerAuthenticatedWithScope(scope string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleErr := func(err error) {
				if errors.Is(err, ErrEmptyAuthHeader) {
					w.Header().Set("WWW-Authenticate", "Bearer")
				}
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
			}
			authHeader := r.Header.Get("Authorization")
			t, err := decodeAndVerifyAuthHeader(authHeader)
			if err != nil {
				log.Printf("Error decoding/verifying auth header: %v\n", err)
				handleErr(err)
				return
			}

			grantedScopes, err := model.ParseScope(t.Claims.Scope)
			if err != nil {
				log.Printf("Error parsing scopes '%s': %v", t.Claims.Scope, err)
				handleErr(err)
				return
			}
			validScope := false
			for _, grantedScope := range grantedScopes {
				if grantedScope == scope {
					validScope = true
				}
			}

			if !validScope {
				handleErr(fmt.Errorf("Token not granted scope: %s", scope))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// DPoPAuthenticated protects token retrieval endpoints by binding access tokens
// to a client, identified via DPoP proofs.
func DPoPAuthenticated() mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleErr := func(err error) {
				if errors.Is(err, ErrEmptyDPoPHeader) {
					w.Header().Set("WWW-Authenticate", "DPoP")
				}
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
			}

			// Verify DPoP information
			dpopEnc := r.Header.Get("DPoP")
			dpop, err := decodeAndVerifyDPoP(dpopEnc)
			if err != nil {
				log.Printf("Error decoding/verifying DPoP token: %v\n", err)
				handleErr(err)
				return
			}
			_ = dpop
		})
	}
}

func decodeAndVerifyAuthHeader(authHeader string) (*jwt.Token, error) {
	if authHeader == "" {
		return nil, ErrEmptyAuthHeader
	}

	bearer, err := ParseBearerAuthorizationHeader(authHeader)
	if err != nil {
		return nil, err
	}

	// Decode and verify JWT token
	token, err := jwt.Decode(bearer)
	if err != nil {
		log.Printf("Error decoding bearer token: %v\n", err)
		return nil, err
	}

	err = token.Verify(config.Current.OAuth.Tokens.PublicKey)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func decodeAndVerifyDPoP(dpopEnc string) (*jwt.Token, error) {
	if dpopEnc == "" {
		return nil, ErrEmptyDPoPHeader
	}

	dpop, err := jwt.Decode(dpopEnc)
	if err != nil {
		return nil, err
	}

	// err = dpop.Verify()
	return dpop, nil
}
