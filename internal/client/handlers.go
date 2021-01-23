package client

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gorilla/mux"
)

const (
	paramaterClientName   = "client_name"
	parameterClientType   = "client_type"
	parameterRedirectURIs = "redirect_uris"
	parameterScopes       = "scopes"
)

// SetupRoutes configures routes for client registration.
func SetupRoutes(r *mux.Router, clientDB database.ClientDB) {
	r.Path("/client/register").
		HandlerFunc(clientRegistrationHandler{clientDB}.handleRegisterClient).
		Methods(http.MethodOptions, http.MethodGet, http.MethodPost)
}

type clientRegistrationHandler struct {
	db database.ClientDB
}

func (h clientRegistrationHandler) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	clientInfo, err := h.db.RegisterClient(ctx, &request, model.ClientOptionNone)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
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
