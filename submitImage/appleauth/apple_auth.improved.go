package appleauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Custom error types for better error handling
type AppleAuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *AppleAuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewAppleAuthError(code, message string, err error) *AppleAuthError {
	return &AppleAuthError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

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
	IdentityToken     string `json:"identityToken" validate:"required"`
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

// Validate validates the Apple auth request
func (r *AppleAuthRequest) Validate() error {
	if strings.TrimSpace(r.IdentityToken) == "" {
		return NewAppleAuthError("INVALID_REQUEST", "Identity token is required", nil)
	}
	
	// Basic JWT format validation
	parts := strings.Split(r.IdentityToken, ".")
	if len(parts) != 3 {
		return NewAppleAuthError("INVALID_TOKEN_FORMAT", "Invalid JWT format", nil)
	}
	
	return nil
}

// AppleAuthResponse represents the response for Apple authentication
type AppleAuthResponse struct {
	Success bool       `json:"success"`
	User    *AppleUser `json:"user,omitempty"`
	Error   string     `json:"error,omitempty"`
	Message string     `json:"message,omitempty"`
}

// AppleAuthService handles Apple ID authentication with improved error handling and caching
type AppleAuthService struct {
	ClientID     string
	TeamID       string
	KeyID        string
	PrivateKey   *rsa.PrivateKey
	
	// Caching and performance
	jwksCache    jwk.Set
	jwksCacheMu  sync.RWMutex
	cacheExpiry  time.Time
	
	// Configuration
	jwksURL      string
	tokenURL     string
	revokeURL    string
	httpClient   *http.Client
	
	// Context for cancellation
	ctx context.Context
}

// AppleAuthServiceConfig holds configuration for the service
type AppleAuthServiceConfig struct {
	ClientID     string
	TeamID       string
	KeyID        string
	PrivateKey   *rsa.PrivateKey
	HTTPTimeout  time.Duration
	CacheTTL     time.Duration
	Context      context.Context
}

// NewAppleAuthService creates a new Apple authentication service with improved configuration
func NewAppleAuthService(config AppleAuthServiceConfig) *AppleAuthService {
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 30 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 24 * time.Hour // Cache JWKS for 24 hours
	}
	if config.Context == nil {
		config.Context = context.Background()
	}

	return &AppleAuthService{
		ClientID:   config.ClientID,
		TeamID:     config.TeamID,
		KeyID:      config.KeyID,
		PrivateKey: config.PrivateKey,
		jwksURL:    "https://appleid.apple.com/auth/keys",
		tokenURL:   "https://appleid.apple.com/auth/token",
		revokeURL:  "https://appleid.apple.com/auth/revoke",
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
		ctx: config.Context,
	}
}

// VerifyIDToken verifies an Apple ID token and returns user information with improved error handling
func (s *AppleAuthService) VerifyIDToken(idToken string) (*AppleUser, error) {
	// Parse the token without verification first to get the header
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &AppleTokenClaims{})
	if err != nil {
		return nil, NewAppleAuthError("PARSE_ERROR", "Failed to parse token", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, NewAppleAuthError("MISSING_KID", "Missing kid in token header", nil)
	}

	// Get Apple's public keys with caching
	publicKey, err := s.getPublicKeyWithCache(kid)
	if err != nil {
		return nil, NewAppleAuthError("KEY_FETCH_ERROR", "Failed to get public key", err)
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
		return nil, NewAppleAuthError("VERIFICATION_ERROR", "Failed to verify token", err)
	}

	if !token.Valid {
		return nil, NewAppleAuthError("INVALID_TOKEN", "Token is invalid", nil)
	}

	// Validate claims
	if err := s.validateClaims(claims); err != nil {
		return nil, err
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

// HandleAuthRequest handles the Apple authentication request with comprehensive validation
func (s *AppleAuthService) HandleAuthRequest(req *AppleAuthRequest) (*AppleAuthResponse, error) {
	// Validate request
	if err := req.Validate(); err != nil {
		return &AppleAuthResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Verify the identity token
	user, err := s.VerifyIDToken(req.IdentityToken)
	if err != nil {
		var appleErr *AppleAuthError
		if errors.As(err, &appleErr) {
			return &AppleAuthResponse{
				Success: false,
				Error:   fmt.Sprintf("Token verification failed: %s", appleErr.Message),
			}, nil
		}
		return &AppleAuthResponse{
			Success: false,
			Error:   fmt.Sprintf("Token verification failed: %v", err),
		}, nil
	}

	// Add user information from the request if available
	if req.User != nil {
		if req.User.Name != nil {
			user.FirstName = strings.TrimSpace(req.User.Name.FirstName)
			user.LastName = strings.TrimSpace(req.User.Name.LastName)
			if user.FirstName != "" || user.LastName != "" {
				user.FullName = strings.TrimSpace(user.FirstName + " " + user.LastName)
			}
		}
		if req.User.Email != "" && user.Email == "" {
			user.Email = req.User.Email
		}
	}

	return &AppleAuthResponse{
		Success: true,
		User:    user,
		Message: "Authentication successful",
	}, nil
}

// getPublicKeyWithCache gets the RSA public key for the given key ID with caching
func (s *AppleAuthService) getPublicKeyWithCache(kid string) (*rsa.PublicKey, error) {
	s.jwksCacheMu.RLock()
	
	// Check if cache is valid and contains the key
	if s.jwksCache != nil && time.Now().Before(s.cacheExpiry) {
		if key, found := s.jwksCache.LookupKeyID(kid); found {
			s.jwksCacheMu.RUnlock()
			
			var rawKey interface{}
			if err := key.Raw(&rawKey); err != nil {
				return nil, fmt.Errorf("failed to get raw key: %w", err)
			}
			
			rsaKey, ok := rawKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("key is not an RSA public key")
			}
			
			return rsaKey, nil
		}
	}
	
	s.jwksCacheMu.RUnlock()

	// Cache miss or expired, fetch new keys
	return s.fetchAndCachePublicKey(kid)
}

// fetchAndCachePublicKey fetches Apple's JWKS and caches it
func (s *AppleAuthService) fetchAndCachePublicKey(kid string) (*rsa.PublicKey, error) {
	s.jwksCacheMu.Lock()
	defer s.jwksCacheMu.Unlock()

	// Double-check pattern
	if s.jwksCache != nil && time.Now().Before(s.cacheExpiry) {
		if key, found := s.jwksCache.LookupKeyID(kid); found {
			var rawKey interface{}
			if err := key.Raw(&rawKey); err != nil {
				return nil, fmt.Errorf("failed to get raw key: %w", err)
			}
			
			rsaKey, ok := rawKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("key is not an RSA public key")
			}
			
			return rsaKey, nil
		}
	}

	// Fetch JWKS from Apple
	req, err := http.NewRequestWithContext(s.ctx, "GET", s.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	// Parse JWKS
	jwksSet, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Cache the JWKS
	s.jwksCache = jwksSet
	s.cacheExpiry = time.Now().Add(24 * time.Hour) // Cache for 24 hours

	// Find the specific key
	key, found := jwksSet.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	}

	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	rsaKey, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaKey, nil
}

// validateClaims validates the Apple ID token claims with comprehensive checks
func (s *AppleAuthService) validateClaims(claims *AppleTokenClaims) error {
	now := time.Now()

	// Check issuer
	if claims.Issuer != "https://appleid.apple.com" {
		return NewAppleAuthError("INVALID_ISSUER", fmt.Sprintf("Invalid issuer: %s", claims.Issuer), nil)
	}

	// Check audience (your client ID)
	if claims.Audience != s.ClientID {
		return NewAppleAuthError("INVALID_AUDIENCE", fmt.Sprintf("Invalid audience: %s", claims.Audience), nil)
	}

	// Check expiration
	if time.Unix(claims.ExpirationTime, 0).Before(now) {
		return NewAppleAuthError("TOKEN_EXPIRED", "Token expired", nil)
	}

	// Check issued at time (not too old - max 24 hours)
	issuedAt := time.Unix(claims.IssuedAt, 0)
	if issuedAt.Before(now.Add(-24 * time.Hour)) {
		return NewAppleAuthError("TOKEN_TOO_OLD", "Token too old", nil)
	}

	// Check issued at time (not in the future - allow 5 minutes clock skew)
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return NewAppleAuthError("TOKEN_FUTURE", "Token issued in the future", nil)
	}

	// Validate subject
	if strings.TrimSpace(claims.Subject) == "" {
		return NewAppleAuthError("MISSING_SUBJECT", "Missing subject in token", nil)
	}

	return nil
}

// generateClientSecret generates a JWT client secret for Apple API calls with proper error handling
func (s *AppleAuthService) generateClientSecret() (string, error) {
	if s.PrivateKey == nil {
		return "", NewAppleAuthError("MISSING_PRIVATE_KEY", "Private key is not configured", nil)
	}

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

	signedToken, err := token.SignedString(s.PrivateKey)
	if err != nil {
		return "", NewAppleAuthError("SIGNING_ERROR", "Failed to sign client secret", err)
	}

	return signedToken, nil
}

// Health check method
func (s *AppleAuthService) HealthCheck() error {
	// Check if we can fetch JWKS
	req, err := http.NewRequestWithContext(s.ctx, "GET", s.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// Close cleans up resources
func (s *AppleAuthService) Close() error {
	// Cancel any ongoing requests
	if cancel, ok := s.ctx.Value("cancel").(context.CancelFunc); ok {
		cancel()
	}
	return nil
}