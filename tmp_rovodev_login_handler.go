package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/atlassian-wcsd/mobile-primary/src/backend/auth"
	"github.com/atlassian-wcsd/mobile-primary/src/backend/logging"
	"github.com/atlassian-wcsd/mobile-primary/src/backend/models"
)

// AppleLoginRequest represents the request payload for Apple Login
type AppleLoginRequest struct {
	IdentityToken     string                 `json:"identityToken" validate:"required"`
	AuthorizationCode string                 `json:"authorizationCode,omitempty"`
	User              map[string]interface{} `json:"user,omitempty"`
	ClientID          string                 `json:"clientId,omitempty"`
}

// AppleLoginResponse represents the response for Apple Login
type AppleLoginResponse struct {
	Success      bool                   `json:"success"`
	User         *models.User           `json:"user,omitempty"`
	Token        string                 `json:"token,omitempty"`
	RefreshToken string                 `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time              `json:"expiresAt,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// LoginHandler handles authentication requests
type LoginHandler struct {
	authService   *auth.AuthService
	loginLogger   *logging.LoginLogger
	rateLimiter   *RateLimiter
}

// NewLoginHandler creates a new LoginHandler instance
func NewLoginHandler(authService *auth.AuthService, loginLogger *logging.LoginLogger) *LoginHandler {
	return &LoginHandler{
		authService: authService,
		loginLogger: loginLogger,
		rateLimiter: NewRateLimiter(100, time.Minute), // 100 requests per minute
	}
}

// HandleAppleLogin processes Apple ID authentication requests
func (h *LoginHandler) HandleAppleLogin(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	h.setCORSHeaders(w)
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		h.sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed, nil)
		return
	}

	// Rate limiting
	clientIP := h.getClientIP(r)
	if !h.rateLimiter.Allow(clientIP) {
		h.loginLogger.LogAppleLoginAttempt(clientIP, "", "RATE_LIMITED", "Rate limit exceeded")
		h.sendErrorResponse(w, "Rate limit exceeded", http.StatusTooManyRequests, nil)
		return
	}

	// Parse request body
	var req AppleLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.loginLogger.LogAppleLoginAttempt(clientIP, "", "INVALID_REQUEST", err.Error())
		h.sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, map[string]interface{}{
			"parseError": err.Error(),
		})
		return
	}

	// Validate required fields
	if err := h.validateAppleLoginRequest(&req); err != nil {
		h.loginLogger.LogAppleLoginAttempt(clientIP, "", "VALIDATION_FAILED", err.Error())
		h.sendErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	}

	// Log login attempt
	h.loginLogger.LogAppleLoginAttempt(clientIP, req.IdentityToken[:20]+"...", "STARTED", "Apple login attempt initiated")

	// Verify Apple ID token
	user, err := h.authService.VerifyAppleIDToken(req.IdentityToken, req.AuthorizationCode, req.User)
	if err != nil {
		h.loginLogger.LogAppleLoginAttempt(clientIP, req.IdentityToken[:20]+"...", "FAILED", err.Error())
		h.sendErrorResponse(w, "Apple authentication failed", http.StatusUnauthorized, map[string]interface{}{
			"authError": err.Error(),
		})
		return
	}

	// Generate session token
	token, refreshToken, expiresAt, err := h.authService.GenerateSessionToken(user)
	if err != nil {
		h.loginLogger.LogAppleLoginAttempt(clientIP, req.IdentityToken[:20]+"...", "TOKEN_FAILED", err.Error())
		h.sendErrorResponse(w, "Failed to generate session token", http.StatusInternalServerError, nil)
		return
	}

	// Log successful login
	h.loginLogger.LogAppleLoginSuccess(clientIP, user.ID, user.Email, "Apple ID authentication successful")

	// Send success response
	response := AppleLoginResponse{
		Success:      true,
		User:         user,
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleAppleRefresh handles Apple token refresh requests
func (h *LoginHandler) HandleAppleRefresh(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		h.sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed, nil)
		return
	}

	var req struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	if req.RefreshToken == "" {
		h.sendErrorResponse(w, "Refresh token is required", http.StatusBadRequest, nil)
		return
	}

	// Refresh the token
	user, token, newRefreshToken, expiresAt, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		h.sendErrorResponse(w, "Token refresh failed", http.StatusUnauthorized, map[string]interface{}{
			"refreshError": err.Error(),
		})
		return
	}

	response := AppleLoginResponse{
		Success:      true,
		User:         user,
		Token:        token,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// validateAppleLoginRequest validates the Apple login request
func (h *LoginHandler) validateAppleLoginRequest(req *AppleLoginRequest) error {
	if req.IdentityToken == "" {
		return fmt.Errorf("identity token is required")
	}

	// Basic JWT format validation
	if len(req.IdentityToken) < 10 {
		return fmt.Errorf("invalid identity token format")
	}

	return nil
}

// setCORSHeaders sets CORS headers for cross-origin requests
func (h *LoginHandler) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// getClientIP extracts client IP from request
func (h *LoginHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// sendErrorResponse sends a standardized error response
func (h *LoginHandler) sendErrorResponse(w http.ResponseWriter, message string, statusCode int, details map[string]interface{}) {
	response := AppleLoginResponse{
		Success: false,
		Error:   message,
		Details: details,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// RateLimiter implements a simple rate limiting mechanism
type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	
	// Clean old requests
	if requests, exists := rl.requests[key]; exists {
		var validRequests []time.Time
		for _, req := range requests {
			if now.Sub(req) < rl.window {
				validRequests = append(validRequests, req)
			}
		}
		rl.requests[key] = validRequests
	}
	
	// Check if limit exceeded
	if len(rl.requests[key]) >= rl.limit {
		return false
	}
	
	// Add current request
	rl.requests[key] = append(rl.requests[key], now)
	return true
}