package admin

import (
	"log"
	"net/http"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	fthttp "github.com/ftauth/ftauth/pkg/http"
	"github.com/ftauth/ftauth/pkg/util/cors"
	"github.com/gorilla/mux"
)

// SetupRoutes configures admin API endpoints
func SetupRoutes(r *mux.Router, clientDB database.ClientDB, scopeDB database.ScopeDB) {
	s := r.PathPrefix("/api/admin").Subrouter()
	s.Use(mux.CORSMethodMiddleware(s))
	s.Use(cors.Middleware)
	m, err := fthttp.NewMiddleware(config.Current.JWKS(false))
	if err != nil {
		log.Fatalln("Error setting up admin routes: ", err)
	}
	s.Use(m.BearerAuthenticatedWithScope("admin"))

	// TODO: REMOVE
	s.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})

	c := clientHandler{clientDB}
	s.HandleFunc("/clients", c.HandleClients).Methods(http.MethodOptions, http.MethodGet, http.MethodPost)
	s.HandleFunc("/clients/{id}", c.HandleClient).Methods(http.MethodOptions, http.MethodGet, http.MethodPut, http.MethodDelete)

	scopes := scopesHandler{scopeDB}
	s.HandleFunc("/scopes", scopes.HandleScopes).Methods(http.MethodOptions, http.MethodGet, http.MethodPost)
	s.HandleFunc("/scopes/{name}", scopes.HandleScope).Methods(http.MethodOptions, http.MethodGet, http.MethodDelete)

}
