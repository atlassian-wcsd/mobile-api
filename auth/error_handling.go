package auth

import (
    "errors"
    "fmt"
)

// LoginError represents an error during the login process.
type LoginError struct {
    Code    int
    Message string
}

// Error implements the error interface for LoginError.
func (e *LoginError) Error() string {
    return fmt.Sprintf("Error %d: %s", e.Code, e.Message)
}

// NewLoginError creates a new LoginError with the given code and message.
func NewLoginError(code int, message string) error {
    return &LoginError{
        Code:    code,
        Message: message,
    }
}

// HandleIncorrectLogin attempts to handle incorrect login attempts.
func HandleIncorrectLogin(attempts int) error {
    if attempts > 3 {
        return NewLoginError(429, "Too many incorrect login attempts. Please try again later.")
    }
    return NewLoginError(401, "Incorrect username or password. Please try again.")
}

// ProvideGuidance provides guidance to the user on resolving login issues.
func ProvideGuidance(err error) string {
    if errors.Is(err, &LoginError{}) {
        switch err.(*LoginError).Code {
        case 429:
            return "You have exceeded the maximum number of login attempts. Please wait a few minutes before trying again."
        case 401:
            return "Please check your username and password and try again. If you have forgotten your password, use the password reset option."
        default:
            return "An unknown error occurred. Please contact support."
        }
    }
    return "An unexpected error occurred. Please try again."
}
