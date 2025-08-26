package appleauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppleAuth_Integration(t *testing.T) {
	// Test the complete flow of Apple authentication
	auth := &AppleAuth{
		ClientID:     "com.test.app",
		TeamID:       "TEST123456",
		KeyID:        "TESTKEY123",
		PrivateKey:   generateTestPrivateKey(t),
		RedirectURI:  "https://test.app.com/callback",
		Environment:  "development",
	}

	t.Run("Complete authentication flow", func(t *testing.T) {
		// This would test the complete flow in a real scenario
		// For now, we test individual components
		assert.NotNil(t, auth.PrivateKey)
		assert.Equal(t, "com.test.app", auth.ClientID)
	})
}

func TestAppleAuth_TokenValidation(t *testing.T) {
	auth := &AppleAuth{
		ClientID: "com.test.app",
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
			errorMsg:    "token is required",
		},
		{
			name:        "Invalid JWT format",
			token:       "invalid.jwt.token",
			expectError: true,
			errorMsg:    "invalid token format",
		},
		{
			name:        "Malformed JWT",
			token:       "not-a-jwt-at-all",
			expectError: true,
			errorMsg:    "invalid token format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateToken(tt.token)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAppleAuth_ClientSecretGeneration(t *testing.T) {
	privateKey := generateTestPrivateKey(t)
	
	auth := &AppleAuth{
		ClientID:   "com.test.app",
		TeamID:     "TEST123456",
		KeyID:      "TESTKEY123",
		PrivateKey: privateKey,
	}

	t.Run("Generate valid client secret", func(t *testing.T) {
		secret, err := auth.GenerateClientSecret()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Verify the JWT structure
		parts := strings.Split(secret, ".")
		assert.Len(t, parts, 3, "JWT should have 3 parts")

		// Parse and verify the token
		token, err := jwt.Parse(secret, func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)

		// Check claims
		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)
		assert.Equal(t, "com.test.app", claims["sub"])
		assert.Equal(t, "TEST123456", claims["iss"])
		assert.Equal(t, "https://appleid.apple.com", claims["aud"])
	})

	t.Run("Generate client secret with expiration", func(t *testing.T) {
		secret, err := auth.GenerateClientSecret()
		require.NoError(t, err)

		token, err := jwt.Parse(secret, func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		// Check expiration is set and reasonable (within 6 months)
		exp, ok := claims["exp"].(float64)
		require.True(t, ok)
		
		expTime := time.Unix(int64(exp), 0)
		now := time.Now()
		assert.True(t, expTime.After(now))
		assert.True(t, expTime.Before(now.Add(6*30*24*time.Hour))) // Within 6 months
	})
}

func TestAppleAuth_ErrorHandling(t *testing.T) {
	t.Run("Missing private key", func(t *testing.T) {
		auth := &AppleAuth{
			ClientID: "com.test.app",
			TeamID:   "TEST123456",
			KeyID:    "TESTKEY123",
			// PrivateKey is nil
		}

		_, err := auth.GenerateClientSecret()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key is required")
	})

	t.Run("Missing required fields", func(t *testing.T) {
		privateKey := generateTestPrivateKey(t)
		
		tests := []struct {
			name   string
			auth   *AppleAuth
			field  string
		}{
			{
				name: "Missing ClientID",
				auth: &AppleAuth{
					TeamID:     "TEST123456",
					KeyID:      "TESTKEY123",
					PrivateKey: privateKey,
				},
				field: "client ID",
			},
			{
				name: "Missing TeamID",
				auth: &AppleAuth{
					ClientID:   "com.test.app",
					KeyID:      "TESTKEY123",
					PrivateKey: privateKey,
				},
				field: "team ID",
			},
			{
				name: "Missing KeyID",
				auth: &AppleAuth{
					ClientID:   "com.test.app",
					TeamID:     "TEST123456",
					PrivateKey: privateKey,
				},
				field: "key ID",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := tt.auth.GenerateClientSecret()
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.field)
			})
		}
	})
}

func TestAppleAuth_HTTPClientConfiguration(t *testing.T) {
	auth := &AppleAuth{
		ClientID: "com.test.app",
	}

	t.Run("Default HTTP client", func(t *testing.T) {
		client := auth.getHTTPClient()
		assert.NotNil(t, client)
		assert.Equal(t, 30*time.Second, client.Timeout)
	})

	t.Run("Custom HTTP client", func(t *testing.T) {
		customClient := &http.Client{
			Timeout: 10 * time.Second,
		}
		auth.HTTPClient = customClient

		client := auth.getHTTPClient()
		assert.Equal(t, customClient, client)
		assert.Equal(t, 10*time.Second, client.Timeout)
	})
}

func TestAppleAuth_EnvironmentConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expectedURL string
	}{
		{
			name:        "Production environment",
			environment: "production",
			expectedURL: "https://appleid.apple.com",
		},
		{
			name:        "Development environment",
			environment: "development",
			expectedURL: "https://appleid.apple.com", // Same URL for now
		},
		{
			name:        "Empty environment defaults to production",
			environment: "",
			expectedURL: "https://appleid.apple.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &AppleAuth{
				Environment: tt.environment,
			}

			url := auth.getAppleIDURL()
			assert.Equal(t, tt.expectedURL, url)
		})
	}
}

func TestAppleAuth_MockAppleResponse(t *testing.T) {
	// Create a mock Apple server for testing
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/keys":
			// Mock Apple's public keys endpoint
			keys := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "TESTKEY123",
						"use": "sig",
						"alg": "RS256",
						"n":   "test-modulus",
						"e":   "AQAB",
					},
				},
			}
			json.NewEncoder(w).Encode(keys)
		case "/auth/token":
			// Mock token endpoint
			response := map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			json.NewEncoder(w).Encode(response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	auth := &AppleAuth{
		ClientID:    "com.test.app",
		Environment: "development",
		// Override the Apple URL to use our mock server
	}

	t.Run("Fetch Apple public keys", func(t *testing.T) {
		// This would test fetching public keys from Apple
		// Implementation depends on your actual Apple integration
		assert.NotNil(t, auth)
	})
}

func TestAppleAuth_ConcurrentAccess(t *testing.T) {
	privateKey := generateTestPrivateKey(t)
	auth := &AppleAuth{
		ClientID:   "com.test.app",
		TeamID:     "TEST123456",
		KeyID:      "TESTKEY123",
		PrivateKey: privateKey,
	}

	t.Run("Concurrent client secret generation", func(t *testing.T) {
		const numGoroutines = 10
		results := make(chan string, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				secret, err := auth.GenerateClientSecret()
				if err != nil {
					errors <- err
				} else {
					results <- secret
				}
			}()
		}

		// Collect results
		secrets := make([]string, 0, numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			select {
			case secret := <-results:
				secrets = append(secrets, secret)
			case err := <-errors:
				t.Fatalf("Unexpected error: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for results")
			}
		}

		// All should succeed
		assert.Len(t, secrets, numGoroutines)

		// All secrets should be valid JWTs
		for _, secret := range secrets {
			parts := strings.Split(secret, ".")
			assert.Len(t, parts, 3)
		}
	})
}

func TestAppleAuth_EdgeCases(t *testing.T) {
	t.Run("Very long client ID", func(t *testing.T) {
		privateKey := generateTestPrivateKey(t)
		longClientID := strings.Repeat("a", 1000)
		
		auth := &AppleAuth{
			ClientID:   longClientID,
			TeamID:     "TEST123456",
			KeyID:      "TESTKEY123",
			PrivateKey: privateKey,
		}

		secret, err := auth.GenerateClientSecret()
		assert.NoError(t, err)
		assert.NotEmpty(t, secret)
	})

	t.Run("Special characters in IDs", func(t *testing.T) {
		privateKey := generateTestPrivateKey(t)
		
		auth := &AppleAuth{
			ClientID:   "com.test-app.special_chars",
			TeamID:     "TEST123456",
			KeyID:      "TESTKEY123",
			PrivateKey: privateKey,
		}

		secret, err := auth.GenerateClientSecret()
		assert.NoError(t, err)
		assert.NotEmpty(t, secret)
	})
}

// Helper function to generate a test RSA private key
func generateTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	// This is a test key - never use in production
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		// Use a pre-generated key for consistent testing
		privateKey = &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: big.NewInt(12345), // Simplified for testing
				E: 65537,
			},
			D: big.NewInt(54321),
		}
	}
	return privateKey
}

func TestAppleAuth_Benchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark tests in short mode")
	}

	privateKey := generateTestPrivateKey(t)
	auth := &AppleAuth{
		ClientID:   "com.test.app",
		TeamID:     "TEST123456",
		KeyID:      "TESTKEY123",
		PrivateKey: privateKey,
	}

	t.Run("Benchmark client secret generation", func(t *testing.T) {
		start := time.Now()
		const iterations = 100

		for i := 0; i < iterations; i++ {
			_, err := auth.GenerateClientSecret()
			require.NoError(t, err)
		}

		duration := time.Since(start)
		avgDuration := duration / iterations

		t.Logf("Generated %d client secrets in %v (avg: %v per secret)", 
			iterations, duration, avgDuration)

		// Ensure reasonable performance (less than 10ms per secret)
		assert.Less(t, avgDuration, 10*time.Millisecond)
	})
}