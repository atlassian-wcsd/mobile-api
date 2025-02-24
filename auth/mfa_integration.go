package auth

import (
    "errors"
    "fmt"
    "time"
)

// MFAService represents a service for handling multi-factor authentication.
type MFAService struct {
    // This could be an interface to a third-party MFA provider
    provider MFAProvider
}

// MFAProvider defines the interface for an MFA provider.
type MFAProvider interface {
    SendToken(userID string) error
    ValidateToken(userID, token string) (bool, error)
}

// NewMFAService creates a new instance of MFAService.
func NewMFAService(provider MFAProvider) *MFAService {
    return &MFAService{provider: provider}
}

// InitiateMFA initiates the MFA process by sending a token to the user.
func (m *MFAService) InitiateMFA(userID string) error {
    err := m.provider.SendToken(userID)
    if err != nil {
        return fmt.Errorf("failed to send MFA token: %w", err)
    }
    return nil
}

// VerifyMFA verifies the provided MFA token.
func (m *MFAService) VerifyMFA(userID, token string) (bool, error) {
    isValid, err := m.provider.ValidateToken(userID, token)
    if err != nil {
        return false, fmt.Errorf("failed to validate MFA token: %w", err)
    }
    return isValid, nil
}

// MockMFAProvider is a mock implementation of the MFAProvider for testing purposes.
type MockMFAProvider struct {
    tokens map[string]string
}

// NewMockMFAProvider creates a new instance of MockMFAProvider.
func NewMockMFAProvider() *MockMFAProvider {
    return &MockMFAProvider{tokens: make(map[string]string)}
}

// SendToken sends a mock token to the user.
func (m *MockMFAProvider) SendToken(userID string) error {
    token := "123456" // In a real implementation, generate a random token
    m.tokens[userID] = token
    fmt.Printf("Sending token %s to user %s\n", token, userID)
    return nil
}

// ValidateToken validates the provided token.
func (m *MockMFAProvider) ValidateToken(userID, token string) (bool, error) {
    if expectedToken, exists := m.tokens[userID]; exists {
        if expectedToken == token {
            return true, nil
        }
        return false, errors.New("invalid token")
    }
    return false, errors.New("token not found")
}
