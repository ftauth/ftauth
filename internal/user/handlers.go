package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/internal/auth"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/util"
	"github.com/gorilla/mux"
)

const (
	forgotPasswordSubject = "forgot-password"
)

// SetupRoutes initializes user routes.
func SetupRoutes(r *mux.Router) {
	r.Handle("/user", auth.BearerAuthenticated(http.HandlerFunc(handleUserInfo)))
	r.HandleFunc("/forgot-password", handleForgotPassword)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Retrieve JWT token from context
	t := r.Context().Value(auth.JwtContextKey)
	if t == nil {
		http.Error(w, "Nil access token", http.StatusInternalServerError)
		return
	}
	token, ok := t.(*jwt.Token)
	if !ok {
		http.Error(w, "Invalid access token", http.StatusInternalServerError)
		return
	}

	userInfo, ok := token.Claims.CustomClaims["userInfo"]
	if !ok {
		http.Error(w, "User info not found", http.StatusBadRequest)
		return
	}

	userInfoMap, ok := userInfo.(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid userInfo format", http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(userInfoMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Write(b)
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		t := r.FormValue("token")
		if t == "" {
			// TODO: Show invalid request page
			http.Error(w, util.ErrMissingParameter("token").Error(), http.StatusBadRequest)
			return
		}

		// Validate token against server public key
		token, err := jwt.Decode(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = token.Verify(config.Current.DefaultVerificationKey())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if token.Claims.Subject != forgotPasswordSubject || token.IsExpired() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		email := r.FormValue("email")
		if email == "" {
			http.Error(w, util.ErrMissingParameter("email").Error(), http.StatusBadRequest)
			return
		}

		// Create short JWT token
		signingKey := config.Current.DefaultSigningKey()
		token := &jwt.Token{
			Header: &jwt.Header{
				Type:      jwt.TypeJWT,
				Algorithm: signingKey.Algorithm,
				KeyID:     signingKey.KeyID,
			},
			Claims: &jwt.Claims{
				ExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				Subject:        forgotPasswordSubject,
			},
		}

		_, err := token.Encode(signingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Email service send email
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}
