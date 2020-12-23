package admin

import (
	"net/http"

	"github.com/dnys1/ftoauth/internal/auth"
	"github.com/gorilla/mux"
)

// SetupRoutes configures admin API endpoints
func SetupRoutes(r *mux.Router) {
	s := r.PathPrefix("/api/admin/").Subrouter()
	s.Use(auth.BearerAuthenticatedWithScope("admin"))
	s.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})
}
