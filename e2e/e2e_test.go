// +build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/dnys1/ftoauth/util/base64url"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newRedirectServer(f http.HandlerFunc) *http.Server {
	r := mux.NewRouter()
	r.HandleFunc("/redirect", f).Methods(http.MethodGet)

	srv := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	return srv
}

const characterSet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~`

func generateCodeChallenge() string {
	N := 128
	numChars := len(characterSet)
	sb := new(strings.Builder)
	for i := 0; i < N; i++ {
		rIdx := rand.Intn(numChars)
		sb.WriteByte(characterSet[rIdx])
	}
	s := sb.String()
	hash := sha256.Sum256([]byte(s))
	return base64url.Encode(hash[:])
}

func TestEndToEnd(t *testing.T) {
	config := &oauth2.Config{
		ClientID:     "e29e6460-61f1-4d55-8541-a10b13375af7",
		ClientSecret: "",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "http://localhost:8080/authorize",
			TokenURL:  "http://localhost:8080/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "http://localhost:8081/redirect",
		Scopes:      []string{"default"},
	}

	codeChallenge := generateCodeChallenge()
	codeChallengeMethod := "S256"

	codeChallengeOpt := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodOpt := oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod)

	state := "state"
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, codeChallengeOpt, codeChallengeMethodOpt)

	t.Log("Please load the following URL in your browser:")
	t.Log(url)

	// No-Headless opts
	// opts := append(chromedp.DefaultExecAllocatorOptions[:2], chromedp.DefaultExecAllocatorOptions[3:]...)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background())
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var code string
	var recState string
	var err string
	var errDesc string
	ch := make(chan struct{})
	srv := newRedirectServer(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		code = query.Get("code")
		recState = query.Get("state")
		err = query.Get("error")
		errDesc = query.Get("error_description")
		cancel()
		close(ch)
	})

	go srv.ListenAndServe()

	usernameSelector := `#username`
	passwordSelector := `#password`
	submitSelector := `#submit`
	chromeErr := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible(usernameSelector),
		chromedp.SendKeys(usernameSelector, "username"),
		chromedp.WaitVisible(passwordSelector),
		chromedp.SendKeys(passwordSelector, "password"),
		chromedp.Click(submitSelector),
	)
	if ctx.Err() != nil {
		// Ignore if we canceled context
	} else {
		require.NoError(t, chromeErr)
	}

	<-ch

	srv.Close()

	require.Emptyf(t, err, "Got error: %s - %s", err, errDesc)
	require.Equal(t, state, recState)
	require.NotEmpty(t, code)

	t.Logf("Got code: %s", code)
	t.Logf("Got state: %s", state)

	// Token Exchange
	exchangeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config.Exchange(exchangeCtx, code, codeChallengeOpt, codeChallengeMethodOpt)
}
