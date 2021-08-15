# About

Fun with JWTs. This repo is just a collection of reasonable vanilla (using
mainly github.com/golang-jwt/jwt) JWT actions. This set of examples will let
you:

* Generate a Signed JWT (`go run ./cmd/create-jwt`)
* Get a JWT from an OAuth2 PKCE Flow (`go run ./cmd/get-jwt-pkce`)
* Validate a JWT using JWKS (`go run ./cmd/check-jwt`)