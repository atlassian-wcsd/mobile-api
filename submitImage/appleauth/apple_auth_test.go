package appleauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAppleAuthService(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	service := NewAppleAuthService("test.client.id", "TEAM123", "KEY123", privateKey)

	assert.Equal(t, "test.client.id", service.ClientID)
	assert.Equal(t, "TEAM123", service.TeamID)
	assert.Equal(t, "KEY123", service.KeyID)
	assert.Equal(t, privateKey, service.PrivateKey)
	assert.Equal(t, "https://appleid.apple.com/auth/keys", service.jwksURL)
	assert.Equal(t, "https://appleid.apple.com/auth/token", service.tokenURL)
	assert.Equal(t, "https://appleid.apple.com/auth/revoke", service.revokeURL)
}

func TestValidateClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	service := NewAppleAuthService("test.client.id", "TEAM123", "KEY123", privateKey)

	tests := []struct {
		name    string
		claims  *AppleTokenClaims
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid claims",
			claims: &AppleTokenClaims{
				Issuer:         "https://appleid.apple.com",
				Audience:       "test.client.id",
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
				IssuedAt:       time.Now().Unix(),
				Subject:        "user123",
			},
			wantErr: false,
		},
		{
			name: "invalid issuer",
			claims: &AppleTokenClaims{
				Issuer:         "https://evil.com",
				Audience:       "test.client.id",
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
				IssuedAt:       time.Now().Unix(),
				Subject:        "user123",
			},
			wantErr: true,
			errMsg:  "invalid issuer",
		},
		{
			name: "invalid audience",
			claims: &AppleTokenClaims{
				Issuer:         "https://appleid.apple.com",
				Audience:       "wrong.client.id",
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
				IssuedAt:       time.Now().Unix(),
				Subject:        "user123",
			},
			wantErr: true,
			errMsg:  "invalid audience",
		},
		{
			name: "expired token",
			claims: &AppleTokenClaims{
				Issuer:         "https://appleid.apple.com",
				Audience:       "test.client.id",
				ExpirationTime: time.Now().Add(-time.Hour).Unix(),
				IssuedAt:       time.Now().Add(-2 * time.Hour).Unix(),
				Subject:        "user123",
			},
			wantErr: true,
			errMsg:  "token expired",
		},
		{
			name: "token too old",
			claims: &AppleTokenClaims{
				Issuer:         "https://appleid.apple.com",
				Audience:       "test.client.id",
				ExpirationTime: time.Now().Add(time.Hour).Unix(),
				IssuedAt:       time.Now().Add(-25 * time.Hour).Unix(),
				Subject:        "user123",
			},
			wantErr: true,
			errMsg:  "token too old",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateClaims(tt.claims)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateClientSecret(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	service := NewAppleAuthService("test.client.id", "TEAM123", "KEY123", privateKey)

	clientSecret, err := service.generateClientSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, clientSecret)

	// Parse the JWT to verify its structure
	token, err := jwt.Parse(clientSecret, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "TEAM123", claims["iss"])
	assert.Equal(t, "https://appleid.apple.com", claims["aud"])
	assert.Equal(t, "test.client.id", claims["sub"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["exp"])

	// Check header
	assert.Equal(t, "KEY123", token.Header["kid"])
	assert.Equal(t, "RS256", token.Header["alg"])
}

func TestHandleAuthRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	service := NewAppleAuthService("test.client.id", "TEAM123", "KEY123", privateKey)

	tests := []struct {
		name    string
		request *AppleAuthRequest
		wantErr bool
	}{
		{
			name: "valid request with user info",
			request: &AppleAuthRequest{
				IdentityToken:     "invalid.token.for.test", // This will fail verification
				AuthorizationCode: "auth_code_123",
				User: &struct {
					Name *struct {
						FirstName string `json:"firstName"`
						LastName  string `json:"lastName"`
					} `json:"name,omitempty"`
					Email string `json:"email,omitempty"`
				}{
					Name: &struct {
						FirstName string `json:"firstName"`
						LastName  string `json:"lastName"`
					}{
						FirstName: "John",
						LastName:  "Doe",
					},
					Email: "john.doe@example.com",
				},
				State: "random_state_123",
			},
			wantErr: true, // Will fail because token verification will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.HandleAuthRequest(tt.request)
			require.NoError(t, err) // HandleAuthRequest doesn't return error, it returns response with error field

			if tt.wantErr {
				assert.False(t, response.Success)
				assert.NotEmpty(t, response.Error)
			} else {
				assert.True(t, response.Success)
				assert.NotNil(t, response.User)
			}
		})
	}
}

func TestAppleUser(t *testing.T) {
	now := time.Now()
	user := &AppleUser{
		ID:             "user123",
		Email:          "user@example.com",
		FirstName:      "John",
		LastName:       "Doe",
		FullName:       "John Doe",
		IsPrivateEmail: false,
		AuthToken:      "token123",
		RefreshToken:   "refresh123",
		ExpiresAt:      now.Add(time.Hour),
		CreatedAt:      now,
		LastLoginAt:    now,
	}

	assert.Equal(t, "user123", user.ID)
	assert.Equal(t, "user@example.com", user.Email)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, "John Doe", user.FullName)
	assert.False(t, user.IsPrivateEmail)
	assert.Equal(t, "token123", user.AuthToken)
	assert.Equal(t, "refresh123", user.RefreshToken)
	assert.True(t, user.ExpiresAt.After(now))
	assert.Equal(t, now.Unix(), user.CreatedAt.Unix())
	assert.Equal(t, now.Unix(), user.LastLoginAt.Unix())
}

func TestAppleAuthRequest(t *testing.T) {
	request := &AppleAuthRequest{
		IdentityToken:     "id_token_123",
		AuthorizationCode: "auth_code_123",
		User: &struct {
			Name *struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name,omitempty"`
			Email string `json:"email,omitempty"`
		}{
			Name: &struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			}{
				FirstName: "Jane",
				LastName:  "Smith",
			},
			Email: "jane.smith@example.com",
		},
		State: "state_123",
	}

	assert.Equal(t, "id_token_123", request.IdentityToken)
	assert.Equal(t, "auth_code_123", request.AuthorizationCode)
	assert.Equal(t, "Jane", request.User.Name.FirstName)
	assert.Equal(t, "Smith", request.User.Name.LastName)
	assert.Equal(t, "jane.smith@example.com", request.User.Email)
	assert.Equal(t, "state_123", request.State)
}

func TestAppleAuthResponse(t *testing.T) {
	user := &AppleUser{
		ID:        "user123",
		Email:     "user@example.com",
		AuthToken: "token123",
	}

	// Success response
	successResponse := &AppleAuthResponse{
		Success: true,
		User:    user,
		Message: "Authentication successful",
	}

	assert.True(t, successResponse.Success)
	assert.NotNil(t, successResponse.User)
	assert.Equal(t, "Authentication successful", successResponse.Message)
	assert.Empty(t, successResponse.Error)

	// Error response
	errorResponse := &AppleAuthResponse{
		Success: false,
		Error:   "Authentication failed",
	}

	assert.False(t, errorResponse.Success)
	assert.Nil(t, errorResponse.User)
	assert.Equal(t, "Authentication failed", errorResponse.Error)
	assert.Empty(t, errorResponse.Message)
}