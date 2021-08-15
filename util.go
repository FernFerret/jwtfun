package jwtdecode

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func GetDevelopmentLogger() (*zap.SugaredLogger, *zap.Logger) {
	config := zap.NewDevelopmentConfig()
	// Don't print a stack trace for our error logs.
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, _ := config.Build()
	return logger.Sugar(), logger
}

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type WellKnownConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	JWKSEndpoint  string `json:"jwks_uri"`
	Issuer        string `json:"issuer"`
}

func LoadWellKnownConfig(url string) (*WellKnownConfig, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC details from %s: %s", url, err)
	}
	defer resp.Body.Close()
	responseData := &WellKnownConfig{}
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to load JSON from OIDC well-known config %s: %s", url, err)
	}
	return responseData, nil
}
