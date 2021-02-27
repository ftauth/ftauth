package model

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/ftauth/ftauth/pkg/jwt"
	"golang.org/x/oauth2"
)

// OAuthConfig holds information needed for performing an OAuth flow.
type OAuthConfig struct {
	Provider  Provider
	JWKSet    *jwt.KeySet
	JWKSetURL string
	*oauth2.Config

	// Protects jwkSet
	mu sync.Mutex
}

// DownloadJWKsIfAvailable downloads the keyset, if available, and not already downloaded.
func (config *OAuthConfig) DownloadJWKsIfAvailable() error {
	config.mu.Lock()
	defer config.mu.Unlock()
	if config.JWKSet != nil {
		return nil
	}

	if config.JWKSetURL == "" {
		return nil
	}

	resp, err := http.Get(config.JWKSetURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == 200 {
		config.JWKSet, err = jwt.DecodeKeySet(string(b))
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%d: %s", resp.StatusCode, b)
	}

	return nil
}
