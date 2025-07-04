package appleauth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppleUser represents a user authenticated via Apple ID
type AppleUser struct {
	ID             string    `json:"id"`
	Email          string    `json:"email,omitempty"`
	FirstName      string    `json:"firstName,omitempty"`
	LastName       string    `json:"lastName,omitempty"`
	FullName       string    `json:"fullName,omitempty"`
	IsPrivateEmail bool      `json:"isPrivateEmail"`
	AuthToken      string    `json:"authToken"`
	RefreshToken   string    `json:"refreshToken,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	LastLoginAt    time.Time `json:"lastLoginAt"`
}

// AppleTokenClaims represents the claims in an Apple ID token
type AppleTokenClaims struct {
	Issuer           string `json:"iss"`
	Audience         string `json:"aud"`
	ExpirationTime   int64  `json:"exp"`
	IssuedAt         int64  `json:"iat"`
	Subject          string `json:"sub"`
	Email            string `json:"email,omitempty"`
	EmailVerified    bool   `json:"email_verified,omitempty"`
	IsPrivateEmail   bool   `json:"is_private_email,omitempty"`
	AuthTime         int64  `json:"auth_time"`
	NonceSupported   bool   `json:"nonce_supported,omitempty"`
	jwt.RegisteredClaims
}

// AppleAuthRequest represents the request payload for Apple authentication
type AppleAuthRequest struct {
	IdentityToken     string `json:"identityToken"`
	AuthorizationCode string `json:"authorizationCode"`
	User              *struct {
		Name *struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name,omitempty"`
		Email string `json:"email,omitempty"`
	} `json:"user,omitempty"`
	State string `json:"state,omitempty"`
}

// AppleAuthResponse represents the response for Apple authentication
type AppleAuthResponse struct {
	Success bool       `json:"success"`
	User    *AppleUser `json:"user,omitempty"`
	Error   string     `json:"error,omitempty"`
	Message string     `json:"message,omitempty"`
}

// AppleJWK represents an Apple JSON Web Key
type AppleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AppleJWKS represents Apple's JSON Web Key Set
type AppleJWKS struct {
	Keys []AppleJWK `json:"keys"`
}

// AppleAuthService handles Apple ID authentication
type AppleAuthService struct {
	ClientID     string
	TeamID       string
	KeyID        string
	PrivateKey   *rsa.PrivateKey
	AppleJWKS    *AppleJWKS
	jwksURL      string
	tokenURL     string
	revokeURL    string
}

// NewAppleAuthService creates a new Apple authentication service
func NewAppleAuthService(clientID, teamID, keyID string, privateKey *rsa.PrivateKey) *AppleAuthService {
	return &AppleAuthService{
		ClientID:   clientID,
		TeamID:     teamID,
		KeyID:      keyID,
		PrivateKey: privateKey,
		jwksURL:    "https://appleid.apple.com/auth/keys",
		tokenURL:   "https://appleid.apple.com/auth/token",
		revokeURL:  "https://appleid.apple.com/auth/revoke",
	}
}

// VerifyIDToken verifies an Apple ID token and returns user information
func (s *AppleAuthService) VerifyIDToken(idToken string) (*AppleUser, error) {
	// Parse the token without verification first to get the header
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &AppleTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	// Get Apple's public keys if not cached
	if s.AppleJWKS == nil {
		if err := s.fetchAppleJWKS(); err != nil {
			return nil, fmt.Errorf("failed to fetch Apple JWKS: %w", err)
		}
	}

	// Find the matching public key
	publicKey, err := s.getPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify the token with the public key
	claims := &AppleTokenClaims{}
	token, err = jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Validate claims
	if err := s.validateClaims(claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	// Create user from claims
	user := &AppleUser{
		ID:             claims.Subject,
		Email:          claims.Email,
		IsPrivateEmail: claims.IsPrivateEmail,
		AuthToken:      idToken,
		ExpiresAt:      time.Unix(claims.ExpirationTime, 0),
		CreatedAt:      time.Now(),
		LastLoginAt:    time.Now(),
	}

	return user, nil
}

// HandleAuthRequest handles the Apple authentication request
func (s *AppleAuthService) HandleAuthRequest(req *AppleAuthRequest) (*AppleAuthResponse, error) {
	// Verify the identity token
	user, err := s.VerifyIDToken(req.IdentityToken)
	if err != nil {
		return &AppleAuthResponse{
			Success: false,
			Error:   fmt.Sprintf("Token verification failed: %v", err),
		}, nil
	}

	// Add user information from the request if available
	if req.User != nil {
		if req.User.Name != nil {
			user.FirstName = req.User.Name.FirstName
			user.LastName = req.User.Name.LastName
			user.FullName = strings.TrimSpace(user.FirstName + " " + user.LastName)
		}
		if req.User.Email != "" && user.Email == "" {
			user.Email = req.User.Email
		}
	}

	// Here you would typically:
	// 1. Save/update user in your database
	// 2. Generate your own JWT token for the user
	// 3. Set up user session

	return &AppleAuthResponse{
		Success: true,
		User:    user,
		Message: "Authentication successful",
	}, nil
}

// RefreshToken refreshes an Apple authentication token
func (s *AppleAuthService) RefreshToken(refreshToken string) (*AppleUser, error) {
	// Create client secret JWT
	clientSecret, err := s.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Prepare token refresh request
	data := map[string]string{
		"client_id":     s.ClientID,
		"client_secret": clientSecret,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	// Make request to Apple's token endpoint
	resp, err := s.makeTokenRequest(data)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}

	// Parse response and verify new ID token
	if resp.IDToken != "" {
		return s.VerifyIDToken(resp.IDToken)
	}

	return nil, fmt.Errorf("no ID token in refresh response")
}

// RevokeToken revokes an Apple refresh token
func (s *AppleAuthService) RevokeToken(refreshToken string) error {
	clientSecret, err := s.generateClientSecret()
	if err != nil {
		return fmt.Errorf("failed to generate client secret: %w", err)
	}

	data := map[string]string{
		"client_id":     s.ClientID,
		"client_secret": clientSecret,
		"token":         refreshToken,
		"token_type_hint": "refresh_token",
	}

	return s.makeRevokeRequest(data)
}

// fetchAppleJWKS fetches Apple's public keys
func (s *AppleAuthService) fetchAppleJWKS() error {
	resp, err := http.Get(s.jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.AppleJWKS = &AppleJWKS{}
	return json.Unmarshal(body, s.AppleJWKS)
}

// getPublicKey gets the RSA public key for the given key ID
func (s *AppleAuthService) getPublicKey(kid string) (*rsa.PublicKey, error) {
	for _, key := range s.AppleJWKS.Keys {
		if key.Kid == kid {
			return s.jwkToRSAPublicKey(&key)
		}
	}
	return nil, fmt.Errorf("key not found for kid: %s", kid)
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func (s *AppleAuthService) jwkToRSAPublicKey(jwk *AppleJWK) (*rsa.PublicKey, error) {
	// This is a simplified implementation
	// In production, you should use a proper JWK library
	// like github.com/lestrrat-go/jwx/v2/jwk
	return nil, fmt.Errorf("JWK to RSA conversion not implemented - use a JWK library")
}

// validateClaims validates the Apple ID token claims
func (s *AppleAuthService) validateClaims(claims *AppleTokenClaims) error {
	// Check issuer
	if claims.Issuer != "https://appleid.apple.com" {
		return fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}

	// Check audience (your client ID)
	if claims.Audience != s.ClientID {
		return fmt.Errorf("invalid audience: %s", claims.Audience)
	}

	// Check expiration
	if time.Unix(claims.ExpirationTime, 0).Before(time.Now()) {
		return fmt.Errorf("token expired")
	}

	// Check issued at time (not too old)
	if time.Unix(claims.IssuedAt, 0).Before(time.Now().Add(-24 * time.Hour)) {
		return fmt.Errorf("token too old")
	}

	return nil
}

// generateClientSecret generates a JWT client secret for Apple API calls
func (s *AppleAuthService) generateClientSecret() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": s.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": s.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.KeyID

	return token.SignedString(s.PrivateKey)
}

// TokenResponse represents Apple's token endpoint response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// makeTokenRequest makes a request to Apple's token endpoint
func (s *AppleAuthService) makeTokenRequest(data map[string]string) (*TokenResponse, error) {
	// Implementation for making HTTP request to Apple's token endpoint
	// This is a placeholder - implement actual HTTP request logic
	return nil, fmt.Errorf("token request not implemented")
}

// makeRevokeRequest makes a request to Apple's revoke endpoint
func (s *AppleAuthService) makeRevokeRequest(data map[string]string) error {
	// Implementation for making HTTP request to Apple's revoke endpoint
	// This is a placeholder - implement actual HTTP request logic
	return fmt.Errorf("revoke request not implemented")
}