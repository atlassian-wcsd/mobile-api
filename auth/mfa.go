package auth

import (
	"errors"
	"fmt"
	"math/rand"
	"net/smtp"
	"time"
)

// MFAService provides multi-factor authentication functionalities.
type MFAService struct {
	verificationCodes map[string]string
}

// NewMFAService creates a new instance of MFAService.
func NewMFAService() *MFAService {
	return &MFAService{
		verificationCodes: make(map[string]string),
	}
}

// GenerateVerificationCode generates a random verification code and sends it to the user via email or SMS.
func (mfa *MFAService) GenerateVerificationCode(userID, contact string) (string, error) {
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	mfa.verificationCodes[userID] = code

	// Simulate sending the code via email or SMS
	if err := sendCode(contact, code); err != nil {
		return "", err
	}

	return code, nil
}

// VerifyCode checks if the provided code matches the stored verification code for the user.
func (mfa *MFAService) VerifyCode(userID, code string) bool {
	storedCode, exists := mfa.verificationCodes[userID]
	if !exists {
		return false
	}

	return storedCode == code
}

// sendCode simulates sending a verification code via email or SMS.
func sendCode(contact, code string) error {
	// This is a placeholder for sending the code via email or SMS.
	// In a real implementation, you would integrate with an email or SMS API.
	fmt.Printf("Sending code %s to %s\n", code, contact)
	return nil
}

// RemoveCode removes the verification code for a user after successful verification.
func (mfa *MFAService) RemoveCode(userID string) {
	delete(mfa.verificationCodes, userID)
}

// Example usage
func main() {
	mfaService := NewMFAService()

	userID := "user123"
	contact := "user@example.com"

	// Generate a verification code
	code, err := mfaService.GenerateVerificationCode(userID, contact)
	if err != nil {
		fmt.Println("Error generating verification code:", err)
		return
	}

	fmt.Println("Verification code sent:", code)

	// Simulate user entering the code
	userEnteredCode := code

	// Verify the code
	if mfaService.VerifyCode(userID, userEnteredCode) {
		fmt.Println("Verification successful!")
		mfaService.RemoveCode(userID)
	} else {
		fmt.Println("Verification failed.")
	}
}
