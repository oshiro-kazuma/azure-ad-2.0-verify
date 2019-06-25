package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

var (
	projectId string
	clientId  string
)

func init() {
	projectId = os.Getenv("PROJECT_ID")
	clientId = os.Getenv("CLIENT_ID")

	if projectId == "" || clientId == "" {
		log.Fatal("PROJECT_ID and CLIENT_ID is required")
	}

	log.Printf("PROJECT_ID: %s, CLIENT_ID:%s", projectId, clientId)
}

func main() {
	http.HandleFunc("/", handlerIndex)
	http.HandleFunc("/parse_id_token", handlerParseIdToken)

	log.Println("Serve: https://localhost:3000")
	log.Fatal(http.ListenAndServeTLS(":3000", "server.crt", "server.key", nil))
}

func handlerIndex(w http.ResponseWriter, r *http.Request) {
	body := `
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <script>
    var idToken = location.hash.substring(10).split("&")[0];
    console.log(idToken);
    if (idToken) {
      fetch('https://localhost:3000/parse_id_token?id_token=' + idToken)
        .then(function(response) {
          return response.json();
        })
        .then(function(json) {
          console.log(JSON.stringify(json));

          document.getElementById('result').insertAdjacentHTML('beforebegin', "<h3>id_token parse 結果</h3>");
          document.getElementById('result').insertAdjacentHTML('beforeend', JSON.stringify(json, null, 4));
        });
    }
  </script>
</head>
<body>
<a href="https://login.microsoftonline.com/` + projectId + `/oauth2/v2.0/authorize?response_type=id_token&scope=openid%20profile&client_id=` + clientId + `&redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fauth%2Flogin%2Fcomplete&nonce=1234&response_mode=fragment">login</a>
<pre id="result"></pre>
</body>
</html>`
	fmt.Fprint(w, body)
}

func handlerParseIdToken(w http.ResponseWriter, r *http.Request) {
	// クエリストリングから id_token を取得
	idToken := r.URL.Query().Get("id_token")

	// キーIDを取得する
	token, err := jws.ParseString(idToken)
	kid, ok := token.Signatures()[0].ProtectedHeaders().Get(jws.KeyIDKey)
	if !ok {
		log.Printf("failed to lookup kid")
	}

	// 公開鍵のセットを取得する
	set, err := jwk.Fetch("https://login.microsoftonline.com/" + projectId + "/discovery/v2.0/keys")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// 対象の公開鍵を取得する
	keys := set.LookupKeyID(kid.(string))
	if len(keys) == 0 {
		log.Printf("failed to lookup key")
		return
	}
	key, err := keys[0].Materialize()
	if err != nil {
		log.Printf("failed to create public key: %s", err)
		return
	}

	// id tokenを検証する
	verified, err := jws.Verify([]byte(idToken), jwa.RS256, key)
	if err != nil {
		log.Printf("failed to verify message: %s", err)
		return
	}

	// jwtをresponseで返す
	fmt.Fprintf(w, string(verified))
}
