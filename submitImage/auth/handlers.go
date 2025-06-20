package auth

import (
	"encoding/json"
	"net/http"
	"time"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfaCode,omitempty"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Success     bool   `json:"success"`
	Token       string `json:"token,omitempty"`
	RequiresMFA bool   `json:"requiresMfa,omitempty"`
	Error       string `json:"error,omitempty"`
}

// User represents a user in the system
type User struct {
	ID                 string    `json:"id"`
	Email              string    `json:"email"`
	PasswordHash       string    `json:"-"`
	MFAEnabled        bool      `json:"mfaEnabled"`
	MFASecret         string    `json:"-"`
	FailedLoginAttempts int      `json:"-"`
	LockedUntil        *time.Time `json:"-"`
	LastLoginAt        *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}

type AuthHandler struct {
	db *dynamodb.DynamoDB
	jwtSecret []byte
	rateLimiter *RateLimiter
}

func NewAuthHandler(db *dynamodb.DynamoDB, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		db: db,
		jwtSecret: []byte(jwtSecret),
		rateLimiter: NewRateLimiter(),
	}
}

// HandleLogin processes login requests
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check rate limiting
	clientIP := r.RemoteAddr
	if h.rateLimiter.IsLimited(clientIP) {
		sendJSONResponse(w, LoginResponse{
			Success: false,
			Error:   "Too many login attempts, please try again later",
		}, http.StatusTooManyRequests)
		return
	}

	// Get user from database
	user, err := h.getUserByEmail(req.Email)
	if err != nil {
		h.rateLimiter.RecordAttempt(clientIP)
		sendJSONResponse(w, LoginResponse{
			Success: false,
			Error:   "Invalid email or password",
		}, http.StatusUnauthorized)
		return
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		sendJSONResponse(w, LoginResponse{
			Success: false,
			Error:   "Account is temporarily locked due to too many failed attempts",
		}, http.StatusUnauthorized)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		h.handleFailedLogin(user)
		h.rateLimiter.RecordAttempt(clientIP)
		sendJSONResponse(w, LoginResponse{
			Success: false,
			Error:   "Invalid email or password",
		}, http.StatusUnauthorized)
		return
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			sendJSONResponse(w, LoginResponse{
				Success:     false,
				RequiresMFA: true,
			}, http.StatusUnauthorized)
			return
		}

		if !h.verifyMFACode(user.MFASecret, req.MFACode) {
			sendJSONResponse(w, LoginResponse{
				Success: false,
				Error:   "Invalid MFA code",
			}, http.StatusUnauthorized)
			return
		}
	}

	// Generate JWT token
	token, err := h.generateToken(user)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Update user's last login time and reset failed attempts
	h.updateLoginSuccess(user)

	sendJSONResponse(w, LoginResponse{
		Success: true,
		Token:   token,
	}, http.StatusOK)
}

// HandlePasswordReset initiates the password reset process
func (h *AuthHandler) HandlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate and store reset token
	token := generateResetToken()
	if err := h.storeResetToken(req.Email, token); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send reset email (implementation depends on email service)
	if err := h.sendResetEmail(req.Email, token); err != nil {
		http.Error(w, "Failed to send reset email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Middleware for authenticating requests
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Validate JWT token
		claims := &jwt.StandardClaims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return h.jwtSecret, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions

func (h *AuthHandler) generateToken(user *User) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   user.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.jwtSecret)
}

func (h *AuthHandler) verifyMFACode(secret, code string) bool {
	// TODO: Implement TOTP verification
	return code == "123456" // Temporary implementation
}

func (h *AuthHandler) handleFailedLogin(user *User) {
	user.FailedLoginAttempts++
	if user.FailedLoginAttempts >= 5 {
		lockUntil := time.Now().Add(15 * time.Minute)
		user.LockedUntil = &lockUntil
	}
	h.updateUser(user)
}

func (h *AuthHandler) updateLoginSuccess(user *User) {
	now := time.Now()
	user.LastLoginAt = &now
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	h.updateUser(user)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Database operations (implement these based on your DynamoDB schema)
func (h *AuthHandler) getUserByEmail(email string) (*User, error) {
	// TODO: Implement DynamoDB query
	return nil, nil
}

func (h *AuthHandler) updateUser(user *User) error {
	// TODO: Implement DynamoDB update
	return nil
}

func (h *AuthHandler) storeResetToken(email, token string) error {
	// TODO: Implement DynamoDB storage
	return nil
}

func (h *AuthHandler) sendResetEmail(email, token string) error {
	// TODO: Implement email sending
	return nil
}