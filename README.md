# 成果物:

[GitHub - funobu/practice_Go_OAuth: GoによるOAuthの実装。](https://github.com/funobu/practice_Go_OAuth)

## ドキュメント:

1. [oauth2](https://pkg.go.dev/golang.org/x/oauth2)
2. [net/http](https://pkg.go.dev/net/http)

## 参考:
[GitHub - duglasmakeyさんのリポジトリ](https://github.com/douglasmakey/oauth2-example)
### Config

主にフェデレーション認証に何を使うかをここで設定する。

```go
var slackOAuthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8000/auth/slack/callback",
	ClientID:     os.Getenv("SLACK_OAUTH_CLIENT_ID"), 
	ClientSecret: os.Getenv("SLACK_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     slack.Endpoint,
}
```

- RedirectURL
    - 認可後のリダイレクト先
- ClientID
    - SlackとかのClientID
- ClientSecret
    - Slackとかのsecret
- Scopes
    - 認可するときに何の権限が欲しいか指定
- Endpoint
    - Endpointの前にslackやgoogleなど使いたい認証基盤を指定

### Login

フェデレーション認証をするために生成したstateトークンを使ってリダイレクトする。

```go
func oauthSlackLogin(w http.ResponseWriter, r *http.Request) {

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	/*
		AuthCodeURL receive state that is a token to protect the user from CSRF attacks. You must always provide a non-empty string and
		validate that it matches the the state query parameter on your redirect callback.
	*/
	u := slackOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}
```

- AuthCodeURL
    - ログインする際の認証基盤へのリダイレクト先のURL
    - 引数にstateというCSRF対策のトークンを追加
- http.Redirect
    - 第3引数にリダイレクト先のURLを追加(今回の場合はAuthCodeURLを代入したuという変数)
    - 第4引数はステータスコード(今回の場合は307でStatusTemporaryRedirect)

### GenerateCookie

CSRF対策のためのstateトークンを生成し、それをクッキーに格納する。

```go
func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
```

### Callback

フェデレーション認証が終わった後に, 返ってきた情報の検証とユーザデータの取得を行う。

- 返ってきた情報は格納されたクッキーと照らし合わせて検証する。

```go
func oauthSlackCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth slack state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromSlack(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	fmt.Fprintf(w, "UserInfo: %s\n", data)
}
```

### GetUserData

```go
func getUserDataFromSlack(code string) ([]byte, error) {
	// Use code to get token and get user info from Slack.

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
```
