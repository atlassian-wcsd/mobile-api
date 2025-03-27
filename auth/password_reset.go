package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/gomail.v2"
)

// Secret key used for signing JWT tokens
var jwtKey = []byte("your_secret_key")

// Email configuration
var smtpHost = "smtp.example.com"
var smtpPort = 587
var smtpUser = "your_email@example.com"
var smtpPass = "your_email_password"

// PasswordResetRequest represents a request to reset a password
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordResetResponse represents a response for a password reset request
type PasswordResetResponse struct {
	Message string `json:"message"`
}

// Claims represents the JWT claims
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// RequestPasswordReset handles password reset requests
func RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequest
	// Parse the request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create a JWT token
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Email: req.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Send the email with the reset link
	resetLink := fmt.Sprintf("https://yourdomain.com/reset-password?token=%s", tokenString)
	if err := sendResetEmail(req.Email, resetLink); err != nil {
		http.Error(w, "Could not send email", http.StatusInternalServerError)
		return
	}

	// Respond to the client
	response := PasswordResetResponse{Message: "Password reset email sent"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendResetEmail sends a password reset email
func sendResetEmail(email, resetLink string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", smtpUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Password Reset Request")
	m.SetBody("text/html", fmt.Sprintf("<p>To reset your password, please click the following link: <a href='%s'>Reset Password</a></p>", resetLink))

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)
	return d.DialAndSend(m)
}
