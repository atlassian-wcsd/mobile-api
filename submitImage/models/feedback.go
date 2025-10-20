package models

import (
	"time"
)

// FeedbackType represents the type of feedback
type FeedbackType string

const (
	FeedbackTypeBugReport        FeedbackType = "bug_report"
	FeedbackTypeFeatureRequest   FeedbackType = "feature_request"
	FeedbackTypeGeneralFeedback  FeedbackType = "general_feedback"
	FeedbackTypeUsabilityIssue   FeedbackType = "usability_issue"
	FeedbackTypePerformanceIssue FeedbackType = "performance_issue"
	FeedbackTypeOther            FeedbackType = "other"
)

// FeedbackStatus represents the status of feedback
type FeedbackStatus string

const (
	FeedbackStatusNew       FeedbackStatus = "new"
	FeedbackStatusInReview  FeedbackStatus = "in_review"
	FeedbackStatusResolved  FeedbackStatus = "resolved"
	FeedbackStatusClosed    FeedbackStatus = "closed"
)

// FeedbackMetadata contains additional metadata about the feedback
type FeedbackMetadata struct {
	AppVersion       string                 `json:"appVersion,omitempty" dynamodbav:"appVersion,omitempty"`
	ScreenResolution string                 `json:"screenResolution,omitempty" dynamodbav:"screenResolution,omitempty"`
	Timestamp        string                 `json:"timestamp,omitempty" dynamodbav:"timestamp,omitempty"`
	URL              string                 `json:"url,omitempty" dynamodbav:"url,omitempty"`
	Context          map[string]interface{} `json:"context,omitempty" dynamodbav:"context,omitempty"`
}

// Feedback represents a user feedback entry
type Feedback struct {
	ID        string            `json:"id" dynamodbav:"id"`
	UserID    string            `json:"userId,omitempty" dynamodbav:"userId,omitempty"`
	Email     string            `json:"email,omitempty" dynamodbav:"email,omitempty"`
	Name      string            `json:"name,omitempty" dynamodbav:"name,omitempty"`
	Type      FeedbackType      `json:"type" dynamodbav:"type"`
	Rating    int               `json:"rating" dynamodbav:"rating"`
	Subject   string            `json:"subject" dynamodbav:"subject"`
	Message   string            `json:"message" dynamodbav:"message"`
	Page      string            `json:"page,omitempty" dynamodbav:"page,omitempty"`
	UserAgent string            `json:"userAgent,omitempty" dynamodbav:"userAgent,omitempty"`
	CreatedAt time.Time         `json:"createdAt" dynamodbav:"createdAt"`
	Status    FeedbackStatus    `json:"status" dynamodbav:"status"`
	Metadata  *FeedbackMetadata `json:"metadata,omitempty" dynamodbav:"metadata,omitempty"`
}

// FeedbackSubmissionRequest represents the request payload for submitting feedback
type FeedbackSubmissionRequest struct {
	Email     string            `json:"email,omitempty"`
	Name      string            `json:"name,omitempty"`
	Type      FeedbackType      `json:"type"`
	Rating    int               `json:"rating"`
	Subject   string            `json:"subject"`
	Message   string            `json:"message"`
	Page      string            `json:"page,omitempty"`
	Metadata  *FeedbackMetadata `json:"metadata,omitempty"`
}

// FeedbackSubmissionResponse represents the response after submitting feedback
type FeedbackSubmissionResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Error      string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
}

// FeedbackListResponse represents the response for listing feedback
type FeedbackListResponse struct {
	Success  bool       `json:"success"`
	Feedback []Feedback `json:"feedback,omitempty"`
	Error    string     `json:"error,omitempty"`
	Count    int        `json:"count"`
}

// Validate validates the feedback submission request
func (req *FeedbackSubmissionRequest) Validate() error {
	if req.Type == "" {
		return NewValidationError("type is required")
	}

	if !isValidFeedbackType(req.Type) {
		return NewValidationError("invalid feedback type")
	}

	if req.Rating < 1 || req.Rating > 5 {
		return NewValidationError("rating must be between 1 and 5")
	}

	if req.Subject == "" {
		return NewValidationError("subject is required")
	}

	if len(req.Subject) > 200 {
		return NewValidationError("subject must be 200 characters or less")
	}

	if req.Message == "" {
		return NewValidationError("message is required")
	}

	if len(req.Message) > 2000 {
		return NewValidationError("message must be 2000 characters or less")
	}

	if req.Email != "" && !isValidEmail(req.Email) {
		return NewValidationError("invalid email format")
	}

	return nil
}

// isValidFeedbackType checks if the feedback type is valid
func isValidFeedbackType(feedbackType FeedbackType) bool {
	validTypes := []FeedbackType{
		FeedbackTypeBugReport,
		FeedbackTypeFeatureRequest,
		FeedbackTypeGeneralFeedback,
		FeedbackTypeUsabilityIssue,
		FeedbackTypePerformanceIssue,
		FeedbackTypeOther,
	}

	for _, validType := range validTypes {
		if feedbackType == validType {
			return true
		}
	}
	return false
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *ValidationError {
	return &ValidationError{Message: message}
}

// isValidEmail validates email format using a simple regex
func isValidEmail(email string) bool {
	// Simple email validation - in production, you might want to use a more robust solution
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	
	// Check for @ symbol
	atIndex := -1
	for i, char := range email {
		if char == '@' {
			if atIndex != -1 {
				return false // Multiple @ symbols
			}
			atIndex = i
		}
	}
	
	if atIndex <= 0 || atIndex >= len(email)-1 {
		return false // @ at beginning, end, or not found
	}
	
	// Check for dot after @
	dotAfterAt := false
	for i := atIndex + 1; i < len(email); i++ {
		if email[i] == '.' {
			dotAfterAt = true
			break
		}
	}
	
	return dotAfterAt
}