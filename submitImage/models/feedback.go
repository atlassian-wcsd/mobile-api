package models

import (
	"time"
)

// Feedback represents a user feedback submission
type Feedback struct {
	ID           string            `json:"id" dynamodb:"id"`
	UserID       string            `json:"userId,omitempty" dynamodb:"userId,omitempty"`
	Email        string            `json:"email,omitempty" dynamodb:"email,omitempty"`
	Rating       int               `json:"rating" dynamodb:"rating"`
	Category     string            `json:"category" dynamodb:"category"`
	Subject      string            `json:"subject" dynamodb:"subject"`
	Message      string            `json:"message" dynamodb:"message"`
	Attachments  []string          `json:"attachments,omitempty" dynamodb:"attachments,omitempty"`
	DeviceInfo   *DeviceInfo       `json:"deviceInfo,omitempty" dynamodb:"deviceInfo,omitempty"`
	CreatedAt    time.Time         `json:"createdAt" dynamodb:"createdAt"`
	Status       string            `json:"status" dynamodb:"status"`
	Response     string            `json:"response,omitempty" dynamodb:"response,omitempty"`
	RespondedAt  *time.Time        `json:"respondedAt,omitempty" dynamodb:"respondedAt,omitempty"`
	RespondedBy  string            `json:"respondedBy,omitempty" dynamodb:"respondedBy,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" dynamodb:"metadata,omitempty"`
}

// DeviceInfo contains information about the user's device and browser
type DeviceInfo struct {
	UserAgent        string    `json:"userAgent" dynamodb:"userAgent"`
	Platform         string    `json:"platform" dynamodb:"platform"`
	ScreenResolution string    `json:"screenResolution" dynamodb:"screenResolution"`
	Viewport         string    `json:"viewport" dynamodb:"viewport"`
	Timestamp        time.Time `json:"timestamp" dynamodb:"timestamp"`
}

// FeedbackSubmissionRequest represents the request payload for submitting feedback
type FeedbackSubmissionRequest struct {
	Rating     int         `json:"rating" validate:"required,min=1,max=5"`
	Category   string      `json:"category" validate:"required"`
	Subject    string      `json:"subject" validate:"required,min=3,max=100"`
	Message    string      `json:"message" validate:"required,min=10,max=2000"`
	Email      string      `json:"email,omitempty" validate:"omitempty,email"`
	DeviceInfo *DeviceInfo `json:"deviceInfo,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
}

// FeedbackSubmissionResponse represents the response after submitting feedback
type FeedbackSubmissionResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
}

// FeedbackListResponse represents the response for listing feedback
type FeedbackListResponse struct {
	Success  bool       `json:"success"`
	Feedback []Feedback `json:"feedback,omitempty"`
	Count    int        `json:"count"`
	Error    string     `json:"error,omitempty"`
}

// FeedbackCategory constants
const (
	CategoryBugReport        = "bug_report"
	CategoryFeatureRequest   = "feature_request"
	CategoryGeneralFeedback  = "general_feedback"
	CategorySupportRequest   = "support_request"
	CategoryPerformanceIssue = "performance_issue"
	CategoryUIUXFeedback     = "ui_ux_feedback"
)

// FeedbackStatus constants
const (
	StatusSubmitted = "submitted"
	StatusInReview  = "in_review"
	StatusResolved  = "resolved"
	StatusClosed    = "closed"
)

// ValidCategories returns a list of valid feedback categories
func ValidCategories() []string {
	return []string{
		CategoryBugReport,
		CategoryFeatureRequest,
		CategoryGeneralFeedback,
		CategorySupportRequest,
		CategoryPerformanceIssue,
		CategoryUIUXFeedback,
	}
}

// IsValidCategory checks if the given category is valid
func IsValidCategory(category string) bool {
	for _, validCategory := range ValidCategories() {
		if category == validCategory {
			return true
		}
	}
	return false
}

// IsValidStatus checks if the given status is valid
func IsValidStatus(status string) bool {
	validStatuses := []string{StatusSubmitted, StatusInReview, StatusResolved, StatusClosed}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}