package auth

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	fthttp "github.com/ftauth/ftauth/pkg/http"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gorilla/mux"
)

type dpopKey string

var (
	dpopContextKey dpopKey = "dpop"
)

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
		return nil, fthttp.ErrInvalidPayload
	}

	// Verify the token was created recently
	if dpop.IssuedBeforeAgo(10 * time.Minute) {
		return nil, fthttp.ErrExpiredToken
	}

	// Verify the same token has not been used before
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	seen, err := in.db.IsTokenSeen(ctx, dpop)
	if err != nil {
		return nil, err
	}
	if seen {
		return nil, fthttp.ErrExpiredToken
	}

	return dpop, nil
}
