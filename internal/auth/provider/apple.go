package provider

import (
	"context"
	"errors"
	"log"
	"net/url"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"golang.org/x/oauth2"
)

type appleProvider struct {
	config  *model.OAuthConfig
	request *model.AuthorizationRequest
}

func newAppleProvider(request *model.AuthorizationRequest) *appleProvider {
	return &appleProvider{
		request: request,
		config: &model.OAuthConfig{
			Provider: model.ProviderApple,
			Config: &oauth2.Config{
				ClientID:    request.ClientID,
				RedirectURL: request.RedirectURI,
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://appleid.apple.com/auth/authorize",
					TokenURL: "https://appleid.apple.com/auth/token",
				},
				Scopes: []string{"name", "email"},
			},
			JWKSetURL: "https://appleid.apple.com/auth/keys",
		},
	}
}

func (ap *appleProvider) GetAuthorizationURL(authRequest *model.AuthorizationRequest) string {
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("response_mode", "query")}
	return ap.config.AuthCodeURL(authRequest.State, opts...)
}

func (ap *appleProvider) Exchange(ctx context.Context, query url.Values) error {
	// The state contained in the Authorize URL.
	state := query.Get("state")

	if state != ap.request.State {
		return errors.New("invalid state")
	}

	if err := query.Get("error"); err != "" {
		// Request has been cancelled.
		// From Apple docs:
		// The only error code that might be returned is user_cancelled_authorize.
		// This error code is returned if the user clicks Cancel during the web flow.

		// TODO: Handle error
	}

	// A JSON web token containing the user’s identity information.
	// We must verify this because we have no other way to get the
	// user's email or any identifying information about them.
	// idTokenJWT := query.Get("id_token")
	// idToken, err := ap.verifyIDToken(idTokenJWT)
	// if err != nil {
	// 	return err
	// }

	// // A single-use authorization code that is valid for five minutes.
	// code := query.Get("code")

	// token, err := ap.config.Exchange(ctx, code)
	// if err != nil {
	// 	return err
	// }

	// TODO: Create user, register provider tokens, generate FTAuth tokens

	return nil
}

func (ap *appleProvider) verifyIDToken(idTokenJWT string) (*jwt.Token, error) {
	if ap.config.JWKSet == nil {
		err := ap.config.DownloadJWKsIfAvailable()
		if err != nil {
			log.Println("Error downloading JWKs: ", err)
			return nil, err
		}
	}

	idToken, err := jwt.Decode(idTokenJWT)
	if err != nil {
		log.Println("Error decoding ID token: ", err)
		return nil, err
	}

	var matchingKey *jwt.Key
	for _, key := range ap.config.JWKSet.Keys {
		if key.KeyID == idToken.Header.KeyID {
			matchingKey = key
			break
		}
	}

	if matchingKey == nil {
		return nil, errors.New("no matching key found to verify ID token")
	}

	err = idToken.Verify(matchingKey)
	if err != nil {
		return nil, errors.New("ID token was not signed with known key")
	}

	return idToken, nil
}
