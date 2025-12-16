package opendevopslambda

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JWTClaims represents the custom claims in our JWT tokens
type JWTClaims struct {
	UserID    string `json:"userId"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	jwt.StandardClaims
}

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey string
	issuer    string
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey, issuer string) *JWTManager {
	return &JWTManager{
		secretKey: secretKey,
		issuer:    issuer,
	}
}

// GenerateToken generates a new JWT token for a user
func (m *JWTManager) GenerateToken(userID, email, firstName, lastName string, expirationHours int) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(expirationHours)).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    m.issuer,
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

// VerifyToken verifies and parses a JWT token
func (m *JWTManager) VerifyToken(tokenString string) (*JWTClaims, error) {
	// Remove "Bearer " prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Check expiration
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// ExtractUserIDFromToken extracts user ID from a JWT token without full verification
// Use this only when you need the user ID for logging or non-critical operations
func (m *JWTManager) ExtractUserIDFromToken(tokenString string) (string, error) {
	claims, err := m.VerifyToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// RefreshToken generates a new token with extended expiration
func (m *JWTManager) RefreshToken(oldTokenString string, expirationHours int) (string, error) {
	claims, err := m.VerifyToken(oldTokenString)
	if err != nil {
		return "", fmt.Errorf("cannot refresh invalid token: %w", err)
	}

	// Generate new token with same user info
	return m.GenerateToken(claims.UserID, claims.Email, claims.FirstName, claims.LastName, expirationHours)
}

// ValidateTokenMiddleware validates JWT token from request header
func (m *JWTManager) ValidateTokenMiddleware(authHeader string) (*JWTClaims, error) {
	if authHeader == "" {
		return nil, errors.New("authorization header is required")
	}

	// Extract token from "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}

	token := parts[1]
	return m.VerifyToken(token)
}
