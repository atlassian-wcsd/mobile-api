package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
	"submit-image/userauth"
)

// UserAuthHandler handles user authentication and registration requests
type UserAuthHandler struct {
	userService  *userauth.UserService
	rateLimiter  *userauth.RateLimiter
	fromEmail    string
	baseURL      string
}

// NewUserAuthHandler creates a new user authentication handler
func NewUserAuthHandler(dynamoDB dynamodbiface.DynamoDBAPI, sesClient sesiface.SESAPI, fromEmail, baseURL string) *UserAuthHandler {
	userService := userauth.NewUserService(dynamoDB, sesClient, fromEmail, baseURL)
	rateLimiter := userauth.NewRateLimiter(dynamoDB)

	return &UserAuthHandler{
		userService: userService,
		rateLimiter: rateLimiter,
		fromEmail:   fromEmail,
		baseURL:     baseURL,
	}
}

// HandleRegister handles user registration requests
func (h *UserAuthHandler) HandleRegister(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get client IP for rate limiting
	clientIP := h.getClientIP(request)
	
	// Check rate limit
	rateLimitConfig := userauth.GetDefaultRegistrationRateLimit()
	allowed, err := h.rateLimiter.CheckRateLimit(clientIP, "register", rateLimitConfig)
	if err != nil {
		log.Printf("Rate limit check failed: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	
	if !allowed {
		remaining, resetTime, _ := h.rateLimiter.GetRemainingRequests(clientIP, "register", rateLimitConfig)
		return h.rateLimitResponse(remaining, resetTime), nil
	}

	// Parse request body
	var regRequest userauth.UserRegistrationRequest
	if err := json.Unmarshal([]byte(request.Body), &regRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Log registration attempt (without sensitive data)
	log.Printf("Registration attempt for username: %s, email: %s", regRequest.Username, regRequest.Email)

	// Register user
	response, err := h.userService.RegisterUser(&regRequest)
	if err != nil {
		log.Printf("Registration failed for %s: %v", regRequest.Username, err)
		return h.errorResponse(500, "Registration failed"), nil
	}

	// If registration failed due to validation or business rules
	if !response.Success {
		return h.errorResponse(400, response.Error), nil
	}

	// Log successful registration
	log.Printf("User registered successfully: %s (ID: %s)", regRequest.Username, response.UserID)

	// Return success response
	responseBody, err := json.Marshal(response)
	if err != nil {
		return h.errorResponse(500, "Failed to marshal response"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 201,
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

// HandleLogin handles user login requests
func (h *UserAuthHandler) HandleLogin(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get client IP for rate limiting
	clientIP := h.getClientIP(request)
	
	// Check rate limit
	rateLimitConfig := userauth.GetDefaultLoginRateLimit()
	allowed, err := h.rateLimiter.CheckRateLimit(clientIP, "login", rateLimitConfig)
	if err != nil {
		log.Printf("Rate limit check failed: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	
	if !allowed {
		remaining, resetTime, _ := h.rateLimiter.GetRemainingRequests(clientIP, "login", rateLimitConfig)
		return h.rateLimitResponse(remaining, resetTime), nil
	}

	// Parse request body
	var loginRequest userauth.UserLoginRequest
	if err := json.Unmarshal([]byte(request.Body), &loginRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Log login attempt (without password)
	log.Printf("Login attempt for username: %s", loginRequest.Username)

	// Authenticate user
	response, err := h.userService.LoginUser(&loginRequest)
	if err != nil {
		log.Printf("Login failed for %s: %v", loginRequest.Username, err)
		return h.errorResponse(500, "Login failed"), nil
	}

	// If login failed
	if !response.Success {
		log.Printf("Login failed for %s: %s", loginRequest.Username, response.Error)
		return h.errorResponse(401, response.Error), nil
	}

	// Log successful login
	log.Printf("User logged in successfully: %s", loginRequest.Username)

	// Return success response
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

// HandleVerifyEmail handles email verification requests
func (h *UserAuthHandler) HandleVerifyEmail(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var verifyRequest userauth.EmailVerificationRequest
	if err := json.Unmarshal([]byte(request.Body), &verifyRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Verify email
	if err := h.userService.VerifyEmail(verifyRequest.Token); err != nil {
		log.Printf("Email verification failed: %v", err)
		return h.errorResponse(400, "Invalid or expired verification token"), nil
	}

	log.Printf("Email verified successfully for token: %s", verifyRequest.Token[:8]+"...")

	response := map[string]interface{}{
		"success": true,
		"message": "Email verified successfully",
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

// HandlePasswordReset handles password reset requests
func (h *UserAuthHandler) HandlePasswordReset(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Get client IP for rate limiting
	clientIP := h.getClientIP(request)
	
	// Check rate limit
	rateLimitConfig := userauth.GetDefaultPasswordResetRateLimit()
	allowed, err := h.rateLimiter.CheckRateLimit(clientIP, "password-reset", rateLimitConfig)
	if err != nil {
		log.Printf("Rate limit check failed: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	
	if !allowed {
		remaining, resetTime, _ := h.rateLimiter.GetRemainingRequests(clientIP, "password-reset", rateLimitConfig)
		return h.rateLimitResponse(remaining, resetTime), nil
	}

	// Parse request body
	var resetRequest userauth.PasswordResetRequest
	if err := json.Unmarshal([]byte(request.Body), &resetRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Request password reset
	if err := h.userService.RequestPasswordReset(resetRequest.Email); err != nil {
		log.Printf("Password reset request failed for %s: %v", resetRequest.Email, err)
		// Don't reveal if email exists for security reasons
	}

	log.Printf("Password reset requested for email: %s", resetRequest.Email)

	response := map[string]interface{}{
		"success": true,
		"message": "If the email exists, a password reset link has been sent",
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

// HandlePasswordResetConfirm handles password reset confirmation requests
func (h *UserAuthHandler) HandlePasswordResetConfirm(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var confirmRequest userauth.PasswordResetConfirmRequest
	if err := json.Unmarshal([]byte(request.Body), &confirmRequest); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Reset password
	if err := h.userService.ResetPassword(confirmRequest.Token, confirmRequest.NewPassword); err != nil {
		log.Printf("Password reset confirmation failed: %v", err)
		return h.errorResponse(400, err.Error()), nil
	}

	log.Printf("Password reset successfully for token: %s", confirmRequest.Token[:8]+"...")

	response := map[string]interface{}{
		"success": true,
		"message": "Password reset successfully",
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

// HandleOptions handles CORS preflight requests
func (h *UserAuthHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
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

// getClientIP extracts the client IP address from the request
func (h *UserAuthHandler) getClientIP(request events.APIGatewayProxyRequest) string {
	// Check X-Forwarded-For header first (common in load balancers)
	if xff := request.Headers["X-Forwarded-For"]; xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := request.Headers["X-Real-IP"]; xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to source IP from request context
	if request.RequestContext.Identity.SourceIP != "" {
		return request.RequestContext.Identity.SourceIP
	}

	// Default fallback
	return "unknown"
}

// errorResponse creates a standardized error response
func (h *UserAuthHandler) errorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
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

// rateLimitResponse creates a rate limit exceeded response
func (h *UserAuthHandler) rateLimitResponse(remaining int, resetTime interface{}) events.APIGatewayProxyResponse {
	errorResp := map[string]interface{}{
		"success":   false,
		"error":     "Rate limit exceeded",
		"remaining": remaining,
		"resetTime": resetTime,
	}

	body, _ := json.Marshal(errorResp)

	return events.APIGatewayProxyResponse{
		StatusCode: 429,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Retry-After":                  "300", // 5 minutes
		},
		Body:            string(body),
		IsBase64Encoded: false,
	}
}