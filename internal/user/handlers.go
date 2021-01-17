package user

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/dnys1/ftoauth/internal/auth"
	"github.com/dnys1/ftoauth/jwt"
	"github.com/gorilla/mux"
)

// SetupRoutes initializes user routes.
func SetupRoutes(r *mux.Router) {
	r.Handle("/user", auth.BearerAuthenticated(http.HandlerFunc(handleUserInfo)))
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Retrieve JWT token from context
	token, ok := r.Context().Value(auth.JwtContextKey).(*jwt.Token)
	if !ok {
		http.Error(w, "Unknown access token.", http.StatusInternalServerError)
		return
	}

	userInfo, ok := token.Claims.CustomClaims["userInfo"]
	if !ok {
		http.Error(w, "User info not found.", http.StatusBadRequest)
		return
	}

	userInfoMap, ok := userInfo.(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid userInfo format.", http.StatusInternalServerError)
		return
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(&userInfoMap); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(b.Bytes())
}
