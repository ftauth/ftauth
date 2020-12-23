package discovery

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/dnys1/ftoauth/internal/database"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/gorilla/mux"
)

// DiscoveryEndpoint is the endpoint for service discovery, as defined by RFC 8414.
const DiscoveryEndpoint = "/.well-known/oauth-authorization-server"

var cond *sync.Cond

// SetupRoutes configures routes for service discovery.
func SetupRoutes(r *mux.Router, discoveryDB database.DiscoveryDB) {
	h := discoveryHandler{discoveryDB: discoveryDB}
	h.needsRefresh = true

	r.Handle(DiscoveryEndpoint, &h).Methods(http.MethodOptions, http.MethodGet)

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
