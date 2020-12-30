package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/database"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/jwt"
	"github.com/dnys1/ftoauth/util/cors"
	"github.com/gorilla/mux"
)

// DiscoveryEndpoint is the endpoint for service discovery, as defined by RFC 8414.
const DiscoveryEndpoint = "/.well-known/oauth-authorization-server"

// JWKSEndpoint is the endpoint for our public JWK set
const JWKSEndpoint = "/jwks.json"

var cond *sync.Cond

// SetupRoutes configures routes for service discovery.
func SetupRoutes(r *mux.Router, discoveryDB database.DiscoveryDB) {
	h := discoveryHandler{discoveryDB: discoveryDB}
	h.needsRefresh = true

	r.Use(mux.CORSMethodMiddleware(r))
	r.Use(cors.Middleware)

	r.Handle(DiscoveryEndpoint, &h).Methods(http.MethodOptions, http.MethodGet)
	r.HandleFunc(JWKSEndpoint, handleJWKS).Methods(http.MethodOptions, http.MethodGet)

	cond = sync.NewCond(&h)
}

type discoveryHandler struct {
	discoveryDB  database.DiscoveryDB
	needsRefresh bool

	metadataJSON []byte
	metadataErr  error // Error loading metadata
	sync.Mutex         // Protects metadataJSON
}

func (h *discoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cond.L.Lock()
	defer cond.L.Unlock()

	if h.needsRefresh {
		go h.loadMetadata(r.Context())
		cond.Wait()
	}

	if h.metadataErr != nil {
		log.Printf("Error retrieving metadata: %v", h.metadataErr)
		http.Error(w, "Error retrieving metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(h.metadataJSON)
}

func (h *discoveryHandler) loadMetadata(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, database.DefaultTimeout)
	defer cancel()

	cond.L.Lock()
	var metadata *model.AuthorizationServerMetadata
	metadata, h.metadataErr = h.discoveryDB.DescribeSelf(ctx)
	if h.metadataErr == nil {
		h.metadataJSON, h.metadataErr = json.Marshal(metadata)
	}
	h.needsRefresh = h.metadataErr != nil
	cond.Broadcast()
	cond.L.Unlock()
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := config.Current.OAuth.Tokens.PublicKey
	jwks := jwt.KeySet{Keys: []*jwt.Key{jwk}}
	b, err := json.Marshal(jwks)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Write(b)
}