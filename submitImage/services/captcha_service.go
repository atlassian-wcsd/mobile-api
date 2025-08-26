package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// CaptchaService handles CAPTCHA verification
type CaptchaService struct {
	secretKey string
	httpClient *http.Client
}

// RecaptchaResponse represents the response from Google reCAPTCHA API
type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
}

// NewCaptchaService creates a new CAPTCHA service
func NewCaptchaService() *CaptchaService {
	secretKey := os.Getenv("RECAPTCHA_SECRET_KEY")
	if secretKey == "" {
		// For development/testing, you might want to use a mock or skip verification
		secretKey = "test-secret-key"
	}
	
	return &CaptchaService{
		secretKey: secretKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// VerifyCaptcha verifies the CAPTCHA token with Google reCAPTCHA
func (s *CaptchaService) VerifyCaptcha(token, clientIP string) error {
	// Skip verification in test mode
	if s.secretKey == "test-secret-key" {
		if token == "test-token" {
			return nil
		}
		return fmt.Errorf("invalid test captcha token")
	}
	
	// Prepare the request to Google reCAPTCHA API
	data := url.Values{}
	data.Set("secret", s.secretKey)
	data.Set("response", token)
	if clientIP != "" {
		data.Set("remoteip", clientIP)
	}
	
	// Make the request
	resp, err := s.httpClient.PostForm("https://www.google.com/recaptcha/api/siteverify", data)
	if err != nil {
		return fmt.Errorf("failed to verify captcha: %w", err)
	}
	defer resp.Body.Close()
	
	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read captcha response: %w", err)
	}
	
	// Parse the response
	var recaptchaResp RecaptchaResponse
	err = json.Unmarshal(body, &recaptchaResp)
	if err != nil {
		return fmt.Errorf("failed to parse captcha response: %w", err)
	}
	
	// Check if verification was successful
	if !recaptchaResp.Success {
		errorMsg := "captcha verification failed"
		if len(recaptchaResp.ErrorCodes) > 0 {
			errorMsg = fmt.Sprintf("captcha verification failed: %v", recaptchaResp.ErrorCodes)
		}
		return fmt.Errorf(errorMsg)
	}
	
	return nil
}

// GetClientIP extracts the client IP from the request
func GetClientIP(headers map[string]string) string {
	// Check for X-Forwarded-For header (common in load balancers)
	if xff := headers["X-Forwarded-For"]; xff != "" {
		return xff
	}
	
	// Check for X-Real-IP header
	if xri := headers["X-Real-IP"]; xri != "" {
		return xri
	}
	
	// Check for CF-Connecting-IP header (Cloudflare)
	if cfip := headers["CF-Connecting-IP"]; cfip != "" {
		return cfip
	}
	
	// Return empty string if no IP found
	return ""
}