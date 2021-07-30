package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"
)

var slackOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://slack.com/oauth/authorize",
	ClientID:     os.Getenv("SLACK_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("SLACK_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://slack.com/api/users.identity"},
	Endpoint:     slack.Endpoint,
}

const oauthSlackUrlAPI = "https://slack.com/oauth/authorize"

func oauthSlackLogin(w http.ResponseWriter, r *http.Request) {

	oauthState := generateStateOauthCookie(w)
	u := slackOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func oauthSlackCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromSlack(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Fprintf(w, "UserInfo: %s\n", data)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromSlack(code string) ([]byte, error) {

	token, err := slackOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthSlackUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

func New() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.Dir("html")))

	mux.HandleFunc("/auth/slack/login", oauthSlackLogin)
	mux.HandleFunc("/auth/slack/callback", oauthSlackCallback)

	return mux
}

func main() {
	server := &http.Server{
		Addr:    fmt.Sprintf(":8000"),
		Handler: New(),
	}

	log.Printf("Starting HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("%v", err)
	} else {
		log.Println("Server closed!")
	}
}
