package userauth

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// User represents a registered user in the system
type User struct {
	ID                string    `json:"id" dynamodb:"id"`
	Username          string    `json:"username" dynamodb:"username"`
	Email             string    `json:"email" dynamodb:"email"`
	PasswordHash      string    `json:"-" dynamodb:"password_hash"` // Never expose in JSON
	Salt              string    `json:"-" dynamodb:"salt"`          // Never expose in JSON
	FullName          string    `json:"fullName,omitempty" dynamodb:"full_name"`
	PhoneNumber       string    `json:"phoneNumber,omitempty" dynamodb:"phone_number"`
	Role              string    `json:"role" dynamodb:"role"`
	EmailVerified     bool      `json:"emailVerified" dynamodb:"email_verified"`
	EmailVerifyToken  string    `json:"-" dynamodb:"email_verify_token"`
	EmailVerifyExpiry time.Time `json:"-" dynamodb:"email_verify_expiry"`
	PasswordResetToken string   `json:"-" dynamodb:"password_reset_token"`
	PasswordResetExpiry time.Time `json:"-" dynamodb:"password_reset_expiry"`
	CreatedAt         time.Time `json:"createdAt" dynamodb:"created_at"`
	UpdatedAt         time.Time `json:"updatedAt" dynamodb:"updated_at"`
	LastLoginAt       *time.Time `json:"lastLoginAt,omitempty" dynamodb:"last_login_at"`
	IsActive          bool      `json:"isActive" dynamodb:"is_active"`
	LoginAttempts     int       `json:"-" dynamodb:"login_attempts"`
	LockedUntil       *time.Time `json:"-" dynamodb:"locked_until"`
}

// UserRegistrationRequest represents the request payload for user registration
type UserRegistrationRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=20"`
	Password    string `json:"password" validate:"required,min=8"`
	Email       string `json:"email" validate:"required,email"`
	FullName    string `json:"fullName,omitempty" validate:"max=100"`
	PhoneNumber string `json:"phoneNumber,omitempty" validate:"max=20"`
}

// UserRegistrationResponse represents the response for user registration
type UserRegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	UserID  string `json:"userId,omitempty"`
	Error   string `json:"error,omitempty"`
}

// UserLoginRequest represents the request payload for user login
type UserLoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// UserLoginResponse represents the response for user login
type UserLoginResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	User         *User  `json:"user,omitempty"`
	Error        string `json:"error,omitempty"`
}

// EmailVerificationRequest represents the request for email verification
type EmailVerificationRequest struct {
	Token string `json:"token" validate:"required"`
}

// PasswordResetRequest represents the request for password reset
type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// PasswordResetConfirmRequest represents the request for password reset confirmation
type PasswordResetConfirmRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// ValidateRegistrationRequest validates the user registration request
func (req *UserRegistrationRequest) Validate() *ValidationErrors {
	var errors []ValidationError

	// Validate username
	if err := validateUsername(req.Username); err != nil {
		errors = append(errors, ValidationError{Field: "username", Message: err.Error()})
	}

	// Validate password
	if err := validatePassword(req.Password); err != nil {
		errors = append(errors, ValidationError{Field: "password", Message: err.Error()})
	}

	// Validate email
	if err := validateEmail(req.Email); err != nil {
		errors = append(errors, ValidationError{Field: "email", Message: err.Error()})
	}

	// Validate full name if provided
	if req.FullName != "" {
		if len(req.FullName) > 100 {
			errors = append(errors, ValidationError{Field: "fullName", Message: "Full name must be less than 100 characters"})
		}
	}

	// Validate phone number if provided
	if req.PhoneNumber != "" {
		if err := validatePhoneNumber(req.PhoneNumber); err != nil {
			errors = append(errors, ValidationError{Field: "phoneNumber", Message: err.Error()})
		}
	}

	if len(errors) > 0 {
		return &ValidationErrors{Errors: errors}
	}

	return nil
}

// validateUsername validates the username according to business rules
func validateUsername(username string) error {
	if len(username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if len(username) > 20 {
		return fmt.Errorf("username must be less than 20 characters long")
	}

	// Username can only contain alphanumeric characters, underscores, and hyphens
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	// Username cannot start or end with underscore or hyphen
	if strings.HasPrefix(username, "_") || strings.HasPrefix(username, "-") ||
		strings.HasSuffix(username, "_") || strings.HasSuffix(username, "-") {
		return fmt.Errorf("username cannot start or end with underscore or hyphen")
	}

	return nil
}

// validatePassword validates the password according to security requirements
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// validateEmail validates the email format
func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	if len(email) > 254 {
		return fmt.Errorf("email address is too long")
	}

	return nil
}

// validatePhoneNumber validates the phone number format
func validatePhoneNumber(phone string) error {
	if phone == "" {
		return nil // Phone number is optional
	}

	// Remove common formatting characters
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "+", "")

	// Check if it contains only digits
	phoneRegex := regexp.MustCompile(`^\d{10,15}$`)
	if !phoneRegex.MatchString(cleanPhone) {
		return fmt.Errorf("phone number must contain 10-15 digits")
	}

	return nil
}

// ToPublicUser returns a user object safe for public consumption (no sensitive data)
func (u *User) ToPublicUser() *User {
	return &User{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		FullName:      u.FullName,
		PhoneNumber:   u.PhoneNumber,
		Role:          u.Role,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
		LastLoginAt:   u.LastLoginAt,
		IsActive:      u.IsActive,
	}
}