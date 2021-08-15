package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc"
	jwtdecode "github.com/fernferret/jwtfun"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/pflag"
)

func main() {

	// Refresh every hour to make sure we didn't reset the keys due to a key-leak
	jwksRefresh := pflag.Duration("jwks-refresh-interval", time.Hour, "set the JWKS refresh interval, defaults to an hour")
	jwksUrl := pflag.String("jwks-url", "", "validate against a JSON Web Key Set (JWKS), must be a url like: https://dex.lab.stokes.nc/keys")
	oidcEndpoint := pflag.String("oidc-well-known", "", "set the .well-known OIDC url, this will automatically set --jwks-url")
	pflag.Parse()

	log, _ := jwtdecode.GetDevelopmentLogger()
	defer log.Sync()

	if *oidcEndpoint != "" {
		cfg, err := jwtdecode.LoadWellKnownConfig(*oidcEndpoint)
		if err != nil {
			log.Fatalf("Failed to load well-known config: %s", err)
		}
		jwksUrl = &cfg.JWKSEndpoint
	}

	if len(pflag.Args()) != 1 {
		log.Fatalf("Expected exactly 1 argument, usage: ./check-jwt <JWT>")
	}

	var keyFunc jwt.Keyfunc
	if *jwksUrl != "" {
		opts := keyfunc.Options{
			RefreshInterval: jwksRefresh,
		}
		jwks, err := keyfunc.Get(*jwksUrl, opts)
		if err != nil {
			log.Fatalf("Failed to load JSON Web Key Set (JWKS) from url '%s': %s", *jwksUrl, err)
		}

		keyFunc = jwks.KeyFunc

	} else {
		privKey := []byte{}
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			return privKey, nil
		}
	}

	myJwt := pflag.Arg(0)
	token, err := jwt.ParseWithClaims(
		myJwt,
		&jwtdecode.CustomClaims{},
		keyFunc,
	)
	if err != nil {
		log.Fatalf("Failed to parse JWT: %s", err)
	}
	claims, ok := token.Claims.(*jwtdecode.CustomClaims)
	if !ok {
		log.Fatalf("Failed to load claims, is JWT malformed?")
	}
	expire := time.Unix(claims.ExpiresAt, 0)
	now := time.Now()
	if !token.Valid {
		log.Error("[DANGER] Token is INVALID")
	}
	if expire.Before(now) {
		log.Errorf("Token is expired, expired at: %v, current time: %v", expire, now)
	}
	data, _ := json.MarshalIndent(token, "", "  ")
	fmt.Println(string(data))

}
