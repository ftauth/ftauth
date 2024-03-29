package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/cors"
	"github.com/gorilla/mux"
)

// DiscoveryEndpoint is the endpoint for service discovery, as defined by RFC 8414.
const DiscoveryEndpoint = "/.well-known/oauth-authorization-server"

// OIDCDiscoveryEndpoint is the endpoint for OIDC provider discovery
const OIDCDiscoveryEndpoint = "/.well-known/openid-configuration"

// JWKSEndpoint is the endpoint for our public JWK set
const JWKSEndpoint = "/jwks.json"

var cond *sync.Cond

// SetupRoutes configures routes for service discovery.
func SetupRoutes(r *mux.Router, discoveryDB database.DiscoveryDB) {
	h := discoveryHandler{discoveryDB: discoveryDB, oidc: false}
	h.needsRefresh = true

	oh := discoveryHandler{discoveryDB: discoveryDB, oidc: true}
	oh.needsRefresh = true

	r.Use(mux.CORSMethodMiddleware(r))
	r.Use(cors.Middleware)

	r.Handle(DiscoveryEndpoint, &h).Methods(http.MethodOptions, http.MethodGet)
	r.Handle(OIDCDiscoveryEndpoint, &oh).Methods(http.MethodOptions, http.MethodGet)
	r.HandleFunc(JWKSEndpoint, handleJWKS).Methods(http.MethodOptions, http.MethodGet)

	cond = sync.NewCond(&h)
}

type discoveryHandler struct {
	discoveryDB  database.DiscoveryDB
	needsRefresh bool
	oidc         bool

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
	cond.L.Lock()
	if h.oidc {
		var metadata *model.OIDCProviderMetadata
		metadata, h.metadataErr = createOIDCMetadata()
		if h.metadataErr == nil {
			h.metadataJSON, h.metadataErr = json.Marshal(metadata)
		}
	} else {
		var metadata *model.AuthorizationServerMetadata
		metadata, h.metadataErr = createMetadata()
		if h.metadataErr == nil {
			h.metadataJSON, h.metadataErr = json.Marshal(metadata)
		}
	}
	h.needsRefresh = h.metadataErr != nil
	cond.Broadcast()
	cond.L.Unlock()
}

func createMetadata() (*model.AuthorizationServerMetadata, error) {
	host := config.Current.Server.URL()
	authEndpoint, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	authEndpoint.Path = path.Join(authEndpoint.Path, "authorize")

	tokenEndpoint, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	tokenEndpoint.Path = path.Join(tokenEndpoint.Path, "token")

	jwksEndpoint, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	jwksEndpoint.Path = path.Join(jwksEndpoint.Path, "jwks.json")

	scopes, err := model.ParseScope(config.Current.OAuth.Scopes.Default)
	if err != nil {
		return nil, err
	}
	scopes = append(scopes, "admin")
	return &model.AuthorizationServerMetadata{
		Issuer:                host,
		AuthorizationEndpoint: authEndpoint.String(),
		TokenEndpoint:         tokenEndpoint.String(),
		JwksURI:               jwksEndpoint.String(),
		ScopesSupported:       scopes,
		ResponseTypesSupported: []model.AuthorizationResponseType{
			model.AuthorizationResponseTypeCode,
			model.AuthorizationResponseTypeToken,
		},
		ResponseModesSupported: []string{"query"},
		GrantTypesSupported: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeClientCredentials,
			model.GrantTypeRefreshToken,
			model.GrantTypeResourceOwnerPasswordCredentials, // TODO: if enabled
		},
		AuthMethodsSupported: []string{"client_secret_basic"},
		AlgorithmsSupported:  config.Current.SupportedAlgorithms(),
		CodeChallengeMethodsSupported: []model.CodeChallengeMethod{
			model.CodeChallengeMethodSHA256,
		},
	}, nil
}

func createOIDCMetadata() (*model.OIDCProviderMetadata, error) {
	metadata, err := createMetadata()
	if err != nil {
		return nil, err
	}

	host := config.Current.Server.URL()
	userInfoEndpoint, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	userInfoEndpoint.Path = path.Join(userInfoEndpoint.Path, "userinfo")

	return &model.OIDCProviderMetadata{
		Issuer:                           metadata.Issuer,
		AuthorizationEndpoint:            metadata.AuthorizationEndpoint,
		TokenEndpoint:                    metadata.TokenEndpoint,
		UserInfoEndpoint:                 userInfoEndpoint.String(),
		JwksURI:                          metadata.JwksURI,
		RegistrationEndpoint:             metadata.RegistrationEndpoint,
		ScopesSupported:                  metadata.ScopesSupported,
		GrantTypesSupported:              metadata.GrantTypesSupported,
		ResponseTypesSupported:           metadata.ResponseTypesSupported,
		ResponseModesSupported:           metadata.ResponseModesSupported,
		AuthMethodsSupported:             metadata.AuthMethodsSupported,
		AlgorithmsSupported:              metadata.AlgorithmsSupported,
		CodeChallengeMethodsSupported:    metadata.CodeChallengeMethodsSupported,
		IdTokenSigningAlgValuesSupported: metadata.AlgorithmsSupported,
		SubjectTypesSupported: []model.SubjectIdentifierType{
			model.SubjectIdentifierTypePublic,
		},
	}, nil
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := config.Current.JWKS(false)
	b, err := json.Marshal(jwks)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Write(b)
}
