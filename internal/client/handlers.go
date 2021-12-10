package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"path"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/discovery"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/cors"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

const (
	paramaterClientName   = "client_name"
	parameterClientType   = "client_type"
	parameterRedirectURIs = "redirect_uris"
	parameterScopes       = "scopes"
)

// SetupRoutes configures routes for client registration.
func SetupRoutes(r *mux.Router, db database.Database) {
	s := r.Path("/client/register").Subrouter()
	s.Use(mux.CORSMethodMiddleware(s))
	s.Use(cors.Middleware)
	s.Handle("", clientRegistrationHandler{db}).
		Methods(http.MethodOptions, http.MethodGet, http.MethodPost)
}

type clientRegistrationHandler struct {
	db database.Database
}

func (h clientRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	var request model.ClientInfo
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Error processing body", http.StatusInternalServerError)
		return
	}

	if request.Name == "" {
		handleRegistrationError(w, model.ClientRegistrationErrorInvalidClientMetadata, paramaterClientName)
		return
	}
	if request.Type == "" {
		handleRegistrationError(w, model.ClientRegistrationErrorInvalidClientMetadata, parameterClientType)
		return
	}
	if len(request.RedirectURIs) == 0 {
		handleRegistrationError(w, model.ClientRegistrationErrorInvalidClientMetadata, parameterRedirectURIs)
		return
	}
	if len(request.Scopes) == 0 {
		handleRegistrationError(w, model.ClientRegistrationErrorInvalidClientMetadata, parameterScopes)
		return
	}

	// Fill in remaining details
	request.ID = uuid.Must(uuid.NewV4()).String()
	if request.Type == model.ClientTypeConfidential {
		reader := rand.Reader
		secret := make([]byte, 32)
		_, err := reader.Read(secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		request.Secret = string(secret)
	}
	request.JWKsURI = path.Join(config.Current.Server.URL(), discovery.JWKSEndpoint)
	request.GrantTypes = []model.GrantType{
		model.GrantTypeAuthorizationCode,
		model.GrantTypeClientCredentials,
		model.GrantTypeRefreshToken,
		model.GrantTypeResourceOwnerPasswordCredentials, // TODO: if enabled
	}
	request.AccessTokenLife = 60 * 60       // 1 hour
	request.RefreshTokenLife = 24 * 60 * 60 // 1 day
	request.Providers = []model.Provider{model.ProviderFTAuth}

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	clientInfo, err := h.db.RegisterClient(ctx, &request, model.ClientOptionNone)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create default user

	{
		userId := uuid.Must(uuid.NewV4())

		passwordHash, err := passwordutil.GeneratePasswordHash("password")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
		defer cancel()
		err = h.db.RegisterUser(ctx, &model.User{
			ID:           userId.String(),
			Username:     "user",
			ClientID:     clientInfo.ID,
			PasswordHash: passwordHash,
			Scopes: []*model.Scope{
				{Name: config.Current.OAuth.Scopes.Default},
			},
		})
		if err != nil {
			log.Printf("Error creating user: %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	if err := json.NewEncoder(w).Encode(clientInfo); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func handleRegistrationError(w http.ResponseWriter, regErr model.ClientRegistrationError, parameter string) {
	errorResponse := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{
		Error:            string(regErr),
		ErrorDescription: regErr.Description(parameter),
	}
	b, err := json.Marshal(errorResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("An unknown error occurred"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(b)
}
