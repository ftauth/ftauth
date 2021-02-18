package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gorilla/mux"
)

// Middleware errors
var (
	ErrEmptyAuthHeader = errors.New("empty auth header")
	ErrEmptyDPoPHeader = errors.New("empty DPoP header")
	ErrInvalidPayload  = errors.New("invalid payload")
	ErrExpiredToken    = errors.New("expired token")
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
		token, err := decodeAndVerifyAuthHeader(authHeader)
		if err != nil {
			log.Printf("Error decoding/verifying auth header: %v\n", err)
			if errors.Is(err, ErrEmptyAuthHeader) {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Attach token to context
		ctx := context.WithValue(r.Context(), JwtContextKey, token)
		r = r.WithContext(ctx)

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

type middlewareInjector struct {
	db database.AuthorizationDB
}

// DPoPAuthenticated protects token retrieval endpoints by binding access tokens
// to a client, identified via DPoP proofs.
func (in *middlewareInjector) DPoPAuthenticated() mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleErr := func(err error) {
				handleTokenRequestError(
					w,
					model.TokenRequestErrInvalidDPoP,
					model.RequestErrorDetails{
						Details: err.Error(),
					},
				)
			}

			// Verify DPoP information, if present
			proof := r.Header.Get("DPoP")
			if proof != "" {
				dpop, err := in.decodeAndVerifyDPoP(proof, r)
				if err != nil {
					log.Printf("Error decoding/verifying DPoP token: %v\n", err)
					handleErr(err)
					return
				}

				// Attach token to context
				ctx := context.WithValue(r.Context(), dpopContextKey, dpop)
				r = r.WithContext(ctx)
			}

			h.ServeHTTP(w, r)
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

	if token.IsExpired() {
		return nil, ErrExpiredToken
	}

	return token, nil
}

func (in *middlewareInjector) decodeAndVerifyDPoP(dpopEnc string, r *http.Request) (*jwt.Token, error) {
	dpop, err := jwt.Decode(dpopEnc)
	if err != nil {
		return nil, err
	}

	// Verify the DPoP signature matches the provided JWK
	err = dpop.Verify(dpop.Header.JWK)
	if err != nil {
		return nil, err
	}

	// Verify the HTTP method and URI match what's encoded in the token
	uri := config.Current.Server.URL() + r.URL.Path
	method := r.Method

	if uri != dpop.Claims.HTTPURI || method != dpop.Claims.HTTPMethod {
		return nil, ErrInvalidPayload
	}

	// Verify the token was created recently
	if dpop.IssuedBeforeAgo(10 * time.Minute) {
		return nil, ErrExpiredToken
	}

	// Verify the same token has not been used before
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err = in.db.IsTokenSeen(ctx, dpop)
	if err != nil {
		return nil, ErrExpiredToken
	}

	return dpop, nil
}
