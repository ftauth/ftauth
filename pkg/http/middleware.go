package fthttp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
)

// Middleware errors
var (
	ErrEmptyAuthHeader = errors.New("empty auth header")
	ErrEmptyDPoPHeader = errors.New("empty DPoP header")
	ErrInvalidPayload  = errors.New("invalid payload")
	ErrExpiredToken    = errors.New("expired token")
)

type jwtKey string

// Context key
var (
	JwtContextKey jwtKey = "jwt"
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

// NewMiddleware creates a middleware factory for FTAuth verification operations.
func NewMiddleware(keySet *jwt.KeySet) (*Middleware, error) {
	for _, key := range keySet.Keys {
		if err := key.IsValid(); err != nil {
			return nil, err
		}
	}
	return &Middleware{
		keySet: keySet,
	}, nil
}

// Middleware provides methods for creating HTTP middleware.
type Middleware struct {
	keySet *jwt.KeySet
}

// BearerAuthenticated protects endpoints based off a user's Bearer auth token.
func (m *Middleware) BearerAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token, err := m.decodeAndVerifyAuthHeader(authHeader)
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
func (m *Middleware) BearerAuthenticatedWithScope(scope string) func(http.Handler) http.Handler {
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
			token, err := m.decodeAndVerifyAuthHeader(authHeader)
			if err != nil {
				log.Printf("Error decoding/verifying auth header: %v\n", err)
				handleErr(err)
				return
			}

			grantedScopes, err := model.ParseScope(token.Claims.Scope)
			if err != nil {
				log.Printf("Error parsing scopes '%s': %v", token.Claims.Scope, err)
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
				handleErr(fmt.Errorf("token not granted scope: %s", scope))
				return
			}

			// Attach token to context
			ctx := context.WithValue(r.Context(), JwtContextKey, token)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// BearerAuthenticatedWithScope protects endpoints based off a user's Bearer auth token
// and the assigned client ID and scope on the bearer token.
func (m *Middleware) BearerAuthenticatedWithClientAndScope(clientID, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleErr := func(err error) {
				w.Header().Set("WWW-Authenticate", "Bearer realm="+clientID)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
			}
			authHeader := r.Header.Get("Authorization")
			token, err := m.decodeAndVerifyAuthHeader(authHeader)
			if err != nil {
				log.Printf("Error decoding/verifying auth header: %v\n", err)
				handleErr(err)
				return
			}

			ftClaims, err := ParseClaims(token)
			if err != nil {
				log.Printf("Error parsing FTAuth claims for token: %s\n%v\n", authHeader, err)
				handleErr(err)
				return
			}

			if ftClaims.ClientID != clientID {
				log.Printf("Invalid client ID: %s\n", ftClaims.ClientID)
				handleErr(ErrInvalidClaims)
				return
			}

			grantedScopes, err := model.ParseScope(token.Claims.Scope)
			if err != nil {
				log.Printf("Error parsing scopes '%s': %v", token.Claims.Scope, err)
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
				handleErr(fmt.Errorf("token not granted scope: %s", scope))
				return
			}

			// Attach token to context
			ctx := context.WithValue(r.Context(), JwtContextKey, token)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) decodeAndVerifyAuthHeader(authHeader string) (*jwt.Token, error) {
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

	verificationKey, err := m.keySet.KeyForAlgorithm(token.Header.Algorithm)
	if err != nil {
		return nil, err
	}
	err = token.Verify(verificationKey)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, ErrExpiredToken
	}

	return token, nil
}
