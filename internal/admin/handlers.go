package admin

import (
	"net/http"

	"github.com/ftauth/ftauth/internal/auth"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/util/cors"
	"github.com/gorilla/mux"
)

// SetupRoutes configures admin API endpoints
func SetupRoutes(r *mux.Router, clientDB database.ClientDB) {
	s := r.PathPrefix("/api/admin").Subrouter()
	s.Use(mux.CORSMethodMiddleware(s))
	s.Use(cors.Middleware)
	s.Use(auth.BearerAuthenticatedWithScope("admin"))
	s.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})

	c := clientHandler{clientDB}
	s.HandleFunc("/clients", c.HandleClients).Methods(http.MethodOptions, http.MethodGet, http.MethodPost)
	s.HandleFunc("/clients/{id}", c.HandleClient).Methods(http.MethodOptions, http.MethodGet, http.MethodPut, http.MethodDelete)
}
