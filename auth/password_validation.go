package auth

import (
	"errors"
	"regexp"
)

// ValidatePasswordStrength checks if the password meets the required strength criteria.
func ValidatePasswordStrength(password string) error {
	// Password must be at least 8 characters long
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	// Password must contain at least one uppercase letter
	uppercasePattern := `[A-Z]`
	if match, _ := regexp.MatchString(uppercasePattern, password); !match {
		return errors.New("password must contain at least one uppercase letter")
	}

	// Password must contain at least one lowercase letter
	lowercasePattern := `[a-z]`
	if match, _ := regexp.MatchString(lowercasePattern, password); !match {
		return errors.New("password must contain at least one lowercase letter")
	}

	// Password must contain at least one digit
	digitPattern := `[0-9]`
	if match, _ := regexp.MatchString(digitPattern, password); !match {
		return errors.New("password must contain at least one digit")
	}

	// Password must contain at least one special character
	specialCharPattern := `[!@#\$%\^&\*]`
	if match, _ := regexp.MatchString(specialCharPattern, password); !match {
		return errors.New("password must contain at least one special character")
	}

	return nil
}
