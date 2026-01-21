package appleauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// AppleJWK represents an Apple JSON Web Key
type AppleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AppleAuthService handles Apple authentication
type AppleAuthService struct {
	// Add any service configuration here
}

// jwkToRSAPublicKey converts an Apple JWK to an RSA public key
// This is the primary implementation using the lestrrat-go/jwx/v2 library
func (s *AppleAuthService) jwkToRSAPublicKey(appleJWK *AppleJWK) (*rsa.PublicKey, error) {
	// Convert Apple JWK to jwx format
	jwkJSON := map[string]interface{}{
		"kty": appleJWK.Kty,
		"kid": appleJWK.Kid,
		"use": appleJWK.Use,
		"alg": appleJWK.Alg,
		"n":   appleJWK.N,
		"e":   appleJWK.E,
	}

	// Marshal to JSON
	jwkBytes, err := json.Marshal(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Parse using jwx library
	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// Extract RSA public key
	var rsaKey rsa.PublicKey
	if err := key.Raw(&rsaKey); err != nil {
		return nil, fmt.Errorf("failed to extract RSA key: %w", err)
	}

	return &rsaKey, nil
}

// jwkToRSAPublicKeyStdLib is an alternative implementation using only standard library
// This can be used if you want to avoid the jwx dependency
func (s *AppleAuthService) jwkToRSAPublicKeyStdLib(jwk *AppleJWK) (*rsa.PublicKey, error) {
	// Decode base64url encoded modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url encoded exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int for modulus
	n := new(big.Int).SetBytes(nBytes)

	// Convert bytes to int for exponent
	var e int
	if len(eBytes) <= 4 {
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
	} else {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
