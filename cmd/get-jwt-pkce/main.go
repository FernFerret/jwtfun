package main

// This is an example go app to perform a PKCE OAuth2 flow. It supports straight
// OIDC .well-known config as well as manually specifying auth/token endpoints.
//
// It's lightly modifed from this gist, so it should now work with any PKCE
// provider, rather than just auth0.
// https://gist.github.com/ogazitt/f749dad9cca8d0ac6607f93a42adf322
//
// I also used jimlambrt's fork of the pkce-code-verifier which uses a
// cryptographic random string rather than math/rand. Without this the PKCE
// tokens are subject to a timing vulnerability, see this for deets:
// https://github.com/nirasan/go-oauth-pkce-code-verifier/pull/1

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	jwtdecode "github.com/fernferret/jwtfun"
	cv "github.com/jimlambrt/go-oauth-pkce-code-verifier"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/pflag"
)

func main() {
	log, _ := jwtdecode.GetDevelopmentLogger()
	defer log.Sync()

	clientID := pflag.String("client-id", "", "set the ClientID for the PKCE OAuth2 flow")
	authEndpoint := pflag.String("auth-endpoint", "https://dex.lab.stokes.nc/auth", "set the 'authorization_endpoint' from the OIDC well-known config")
	tokenEndpoint := pflag.String("token-endpoint", "https://dex.lab.stokes.nc/auth", "set the 'token_endpoint' from the OIDC well-known config")
	oidcEndpoint := pflag.String("oidc-well-known", "", "set the .well-known url, this will automatically set --auth-endpoint and --token-endpoint ")
	callbackURL := pflag.String("bind", "http://localhost:17000", "set the callback url")
	pflag.Parse()
	if *clientID == "" {
		log.Warn("Missing --client-id, using empty client-id, this is likely not what you want and probably won't work.")
	}

	if *oidcEndpoint != "" {
		cfg, err := jwtdecode.LoadWellKnownConfig(*oidcEndpoint)
		if err != nil {
			log.Fatalf("Failed to load well-known config: %s", err)
		}
		tokenEndpoint = &cfg.TokenEndpoint
		authEndpoint = &cfg.AuthEndpoint
	}

	AuthorizeUser(*clientID, *authEndpoint, *tokenEndpoint, *callbackURL)
}

// AuthorizeUser implements the PKCE OAuth2 flow.
func AuthorizeUser(clientID string, authEndpoint, tokenEndpoint string, redirectURL string) {
	// initialize the code verifier
	var CodeVerifier, _ = cv.CreateCodeVerifier()

	// Create code_challenge with S256 method
	codeChallenge := CodeVerifier.CodeChallengeS256()

	// construct the authorization URL (with Auth0 as the authorization provider)
	authorizationURL := fmt.Sprintf(
		"%s?audience=https://api.stokes.nc"+
			"&scope=openid"+
			"&response_type=code&client_id=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256&redirect_uri=%s",
		authEndpoint, clientID, codeChallenge, redirectURL)

	// start a web server to listen on a callback URL
	server := &http.Server{Addr: redirectURL}

	// define a handler that will get the authorization code, call the token endpoint, and close the HTTP server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			fmt.Println("Url Param 'code' is missing")
			io.WriteString(w, "Error: could not find 'code' URL parameter\n")

			// close the HTTP server and return
			cleanup(server)
			return
		}

		// trade the authorization code and the code verifier for an access token
		codeVerifier := CodeVerifier.String()
		token, err := getAccessToken(clientID, codeVerifier, code, redirectURL, tokenEndpoint)
		if err != nil {
			fmt.Println("could not get access token")
			io.WriteString(w, "Error: could not retrieve access token\n")

			// close the HTTP server and return
			cleanup(server)
			return
		}

		// viper.Set("AccessToken", token)
		// err = viper.WriteConfig()
		//_, err = config.WriteConfigFile("auth.json", token)
		// if err != nil {
		// 	fmt.Println("could not write config file")
		// 	io.WriteString(w, "Error: could not store access token\n")

		// 	// close the HTTP server and return
		// 	cleanup(server)
		// 	return
		// }
		fmt.Println(token)

		// return an indication of success to the caller
		io.WriteString(w, `
		<html>
			<body>
				<h1>Login successful!</h1>
				<h2>You can close this window.</h2>
			</body>
		</html>`)

		fmt.Println("Successfully logged in.")

		// close the HTTP server
		cleanup(server)
	})

	// parse the redirect URL for the port number
	u, err := url.Parse(redirectURL)
	if err != nil {
		fmt.Printf("bad redirect URL: %s\n", err)
		os.Exit(1)
	}

	// set up a listener on the redirect port
	port := fmt.Sprintf(":%s", u.Port())
	l, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Printf("can't listen to port %s: %s\n", port, err)
		os.Exit(1)
	}

	// open a browser window to the authorizationURL
	err = open.Start(authorizationURL)
	if err != nil {
		fmt.Printf("can't open browser to URL %s: %s\n", authorizationURL, err)
		os.Exit(1)
	}

	// start the blocking web server loop
	// this will exit when the handler gets fired and calls server.Close()
	server.Serve(l)
}

// getAccessToken trades the authorization code retrieved from the first OAuth2 leg for an access token
func getAccessToken(clientID, codeVerifier, authorizationCode, callbackURL, tokenEndpoint string) (string, error) {
	// set the url and form-encoded data for the POST to the access token endpoint
	data := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s"+
			"&code_verifier=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		clientID, codeVerifier, authorizationCode, callbackURL)
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", tokenEndpoint, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("HTTP error: %s", err)
		return "", err
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := ioutil.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Printf("JSON error: %s", err)
		return "", err
	}

	str, _ := json.MarshalIndent(responseData, "", "  ")
	fmt.Println(string(str))

	// retrieve the access token out of the map, and return to caller
	accessToken := responseData["access_token"].(string)
	return accessToken, nil
}

// cleanup closes the HTTP server
func cleanup(server *http.Server) {
	// we run this as a goroutine so that this function falls through and
	// the socket to the browser gets flushed/closed before the server goes away
	go server.Close()
}
