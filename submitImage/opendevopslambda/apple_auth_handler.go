package opendevopslambda

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"submit-image/appleauth"

	"github.com/aws/aws-lambda-go/events"
)

// AppleAuthHandler handles Apple authentication requests
type AppleAuthHandler struct {
	appleAuthService *appleauth.AppleAuthService
}

// NewAppleAuthHandler creates a new Apple authentication handler
func NewAppleAuthHandler() (*AppleAuthHandler, error) {
	// Get configuration from environment variables
	clientID := os.Getenv("APPLE_CLIENT_ID")
	teamID := os.Getenv("APPLE_TEAM_ID")
	keyID := os.Getenv("APPLE_KEY_ID")
	privateKeyPEM := os.Getenv("APPLE_PRIVATE_KEY")

	if clientID == "" || teamID == "" || keyID == "" || privateKeyPEM == "" {
		return nil, fmt.Errorf("missing required Apple configuration environment variables")
	}

	// Parse the private key (in production, you'd want proper key parsing)
	// For now, this is a placeholder - you'll need to implement proper PEM parsing
	var privateKey *rsa.PrivateKey
	// privateKey = parsePrivateKeyFromPEM(privateKeyPEM)

	service := appleauth.NewAppleAuthService(clientID, teamID, keyID, privateKey)

	return &AppleAuthHandler{
		appleAuthService: service,
	}, nil
}

// HandleVerifyToken handles Apple ID token verification
func (h *AppleAuthHandler) HandleVerifyToken(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var authRequest appleauth.AppleAuthRequest
	if err := json.Unmarshal([]byte(request.Body), &authRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Validate required fields
	if authRequest.IdentityToken == "" {
		return h.errorResponse(400, "Identity token is required"), nil
	}

	// Process the authentication request
	response, err := h.appleAuthService.HandleAuthRequest(&authRequest)
	if err != nil {
		return h.errorResponse(500, fmt.Sprintf("Authentication processing failed: %v", err)), nil
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(500, "Failed to marshal response"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(responseBody),
		IsBase64Encoded: false,
	}, nil
}

// HandleRefreshToken handles Apple token refresh
func (h *AppleAuthHandler) HandleRefreshToken(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var refreshRequest struct {
		RefreshToken string `json:"refreshToken"`
	}
	
	if err := json.Unmarshal([]byte(request.Body), &refreshRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	if refreshRequest.RefreshToken == "" {
		return h.errorResponse(400, "Refresh token is required"), nil
	}

	// Refresh the token
	user, err := h.appleAuthService.RefreshToken(refreshRequest.RefreshToken)
	if err != nil {
		return h.errorResponse(401, fmt.Sprintf("Token refresh failed: %v", err)), nil
	}

	// Create response
	response := &appleauth.AppleAuthResponse{
		Success: true,
		User:    user,
		Message: "Token refreshed successfully",
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(500, "Failed to marshal response"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(responseBody),
		IsBase64Encoded: false,
	}, nil
}

// HandleSignOut handles Apple sign out
func (h *AppleAuthHandler) HandleSignOut(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		return h.errorResponse(401, "Authorization header required"), nil
	}

	// Extract token from "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return h.errorResponse(401, "Invalid authorization header format"), nil
	}

	token := parts[1]

	// Parse request body for refresh token
	var signOutRequest struct {
		RefreshToken string `json:"refreshToken"`
	}
	
	if request.Body != "" {
		if err := json.Unmarshal([]byte(request.Body), &signOutRequest); err != nil {
			return h.errorResponse(400, "Invalid request body"), nil
		}
	}

	// Revoke refresh token if provided
	if signOutRequest.RefreshToken != "" {
		if err := h.appleAuthService.RevokeToken(signOutRequest.RefreshToken); err != nil {
			// Log error but don't fail the sign out
			fmt.Printf("Failed to revoke refresh token: %v\n", err)
		}
	}

	// Here you would typically:
	// 1. Invalidate the user session in your database
	// 2. Add the token to a blacklist
	// 3. Clean up any user-specific data

	response := map[string]interface{}{
		"success": true,
		"message": "Signed out successfully",
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(500, "Failed to marshal response"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(responseBody),
		IsBase64Encoded: false,
	}, nil
}

// HandleGetProfile handles getting user profile
func (h *AppleAuthHandler) HandleGetProfile(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		return h.errorResponse(401, "Authorization header required"), nil
	}

	// Extract token from "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return h.errorResponse(401, "Invalid authorization header format"), nil
	}

	token := parts[1]

	// Verify the token and get user information
	user, err := h.appleAuthService.VerifyIDToken(token)
	if err != nil {
		return h.errorResponse(401, fmt.Sprintf("Invalid token: %v", err)), nil
	}

	// Here you would typically fetch additional user data from your database
	// For now, we'll return the user from the token

	response := &appleauth.AppleAuthResponse{
		Success: true,
		User:    user,
		Message: "Profile retrieved successfully",
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(500, "Failed to marshal response"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(responseBody),
		IsBase64Encoded: false,
	}, nil
}

// HandleOptions handles CORS preflight requests
func (h *AppleAuthHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
		Body:            "",
		IsBase64Encoded: false,
	}, nil
}

// errorResponse creates a standardized error response
func (h *AppleAuthHandler) errorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	errorResp := map[string]interface{}{
		"success": false,
		"error":   message,
	}

	body, _ := json.Marshal(errorResp)

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(body),
		IsBase64Encoded: false,
	}
}