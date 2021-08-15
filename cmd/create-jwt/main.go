package main

import (
	"time"

	jwtdecode "github.com/fernferret/jwtfun"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/pflag"
)

var hmacSampleSecret []byte

func main() {
	pflag.Parse()

	claims := jwtdecode.CustomClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// 5 Min expiry
			ExpiresAt: time.Now().Add(300 * time.Second).Unix(),
			Issuer:    "stokesnet",
		},
	}

	log, logger := jwtdecode.GetDevelopmentLogger()
	defer logger.Sync()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	if err != nil {
		log.Fatalf("Could not create signed JWT, err: %s", err)
	}
	log.Infof("JWT is: %s", tokenString)
}
