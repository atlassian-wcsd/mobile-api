package models

import (
	"fmt"
	"time"
	"regexp"
	"strings"
	"golang.org/x/crypto/bcrypt"
)

// User represents a registered user in the system
type User struct {
	ID                string    `json:"id" dynamodb:"id"`
	Username          string    `json:"username" dynamodb:"username"`
	Email             string    `json:"email" dynamodb:"email"`
	PasswordHash      string    `json:"-" dynamodb:"password_hash"` // Never expose in JSON
	FirstName         string    `json:"firstName,omitempty" dynamodb:"first_name"`
	LastName          string    `json:"lastName,omitempty" dynamodb:"last_name"`
	ProfilePicture    string    `json:"profilePicture,omitempty" dynamodb:"profile_picture"`
	Bio               string    `json:"bio,omitempty" dynamodb:"bio"`
	EmailVerified     bool      `json:"emailVerified" dynamodb:"email_verified"`
	EmailVerifyToken  string    `json:"-" dynamodb:"email_verify_token"` // Never expose in JSON
	TermsAccepted     bool      `json:"termsAccepted" dynamodb:"terms_accepted"`
	PrivacyAccepted   bool      `json:"privacyAccepted" dynamodb:"privacy_accepted"`
	CreatedAt         time.Time `json:"createdAt" dynamodb:"created_at"`
	UpdatedAt         time.Time `json:"updatedAt" dynamodb:"updated_at"`
	LastLoginAt       *time.Time `json:"lastLoginAt,omitempty" dynamodb:"last_login_at"`
	IsActive          bool      `json:"isActive" dynamodb:"is_active"`
}

// UserRegistrationRequest represents the request payload for user registration
type UserRegistrationRequest struct {
	Username        string `json:"username" validate:"required,min=3,max=30"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirmPassword" validate:"required"`
	FirstName       string `json:"firstName,omitempty" validate:"max=50"`
	LastName        string `json:"lastName,omitempty" validate:"max=50"`
	ProfilePicture  string `json:"profilePicture,omitempty"`
	Bio             string `json:"bio,omitempty" validate:"max=500"`
	TermsAccepted   bool   `json:"termsAccepted" validate:"required"`
	PrivacyAccepted bool   `json:"privacyAccepted" validate:"required"`
	CaptchaToken    string `json:"captchaToken" validate:"required"`
}

// UserRegistrationResponse represents the response after successful registration
type UserRegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	UserID  string `json:"userId,omitempty"`
	Error   string `json:"error,omitempty"`
}

// EmailVerificationRequest represents the request to verify email
type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
}

// EmailVerificationResponse represents the response after email verification
type EmailVerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// ValidatePassword checks if password meets security requirements
func (u *UserRegistrationRequest) ValidatePassword() error {
	if len(u.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	
	if u.Password != u.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}
	
	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(u.Password)
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	
	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(u.Password)
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	
	// Check for at least one digit
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(u.Password)
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	
	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(u.Password)
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}
	
	return nil
}

// ValidateEmail checks if email format is valid
func (u *UserRegistrationRequest) ValidateEmail() error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(u.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidateUsername checks if username meets requirements
func (u *UserRegistrationRequest) ValidateUsername() error {
	if len(u.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	
	if len(u.Username) > 30 {
		return fmt.Errorf("username must be no more than 30 characters long")
	}
	
	// Username can only contain alphanumeric characters and underscores
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !usernameRegex.MatchString(u.Username) {
		return fmt.Errorf("username can only contain letters, numbers, and underscores")
	}
	
	return nil
}

// ValidateTermsAndPrivacy checks if user accepted required agreements
func (u *UserRegistrationRequest) ValidateTermsAndPrivacy() error {
	if !u.TermsAccepted {
		return fmt.Errorf("you must accept the terms and conditions")
	}
	
	if !u.PrivacyAccepted {
		return fmt.Errorf("you must accept the privacy policy")
	}
	
	return nil
}

// HashPassword creates a bcrypt hash of the password
func (u *User) HashPassword(password string) error {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedBytes)
	return nil
}

// CheckPassword verifies if the provided password matches the stored hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// SanitizeForResponse removes sensitive fields before sending user data in response
func (u *User) SanitizeForResponse() *User {
	sanitized := *u
	sanitized.PasswordHash = ""
	sanitized.EmailVerifyToken = ""
	return &sanitized
}