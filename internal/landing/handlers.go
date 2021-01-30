package landing

import (
	"net/http"

	"github.com/gorilla/mux"
)

// SetupRoutes initializes routes for the landing page, including
// static site and email signup.
func SetupRoutes(r *mux.Router, templateDir string) {
	r.Path("/signup").HandlerFunc(handleEmailSignup).Methods(http.MethodPost)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(templateDir)))
}

func handleEmailSignup(w http.ResponseWriter, r *http.Request) {

}
