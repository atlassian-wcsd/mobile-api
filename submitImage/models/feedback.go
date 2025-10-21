package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/google/uuid"
)

// FeedbackCategory represents the type of feedback
type FeedbackCategory string

const (
	BugReport        FeedbackCategory = "bug_report"
	FeatureRequest   FeedbackCategory = "feature_request"
	GeneralFeedback  FeedbackCategory = "general_feedback"
	UserExperience   FeedbackCategory = "user_experience"
	Performance      FeedbackCategory = "performance"
	Other            FeedbackCategory = "other"
)

// FeedbackStatus represents the current status of feedback
type FeedbackStatus string

const (
	Submitted  FeedbackStatus = "submitted"
	Reviewed   FeedbackStatus = "reviewed"
	InProgress FeedbackStatus = "in_progress"
	Resolved   FeedbackStatus = "resolved"
	Closed     FeedbackStatus = "closed"
)

// DeviceInfo contains information about the user's device
type DeviceInfo struct {
	UserAgent        string `json:"userAgent" dynamodbav:"userAgent"`
	Platform         string `json:"platform" dynamodbav:"platform"`
	ScreenResolution string `json:"screenResolution" dynamodbav:"screenResolution"`
	Viewport         string `json:"viewport" dynamodbav:"viewport"`
	Language         string `json:"language" dynamodbav:"language"`
	Timezone         string `json:"timezone" dynamodbav:"timezone"`
}

// FeedbackMetadata contains additional context about the feedback
type FeedbackMetadata struct {
	AppVersion  string `json:"appVersion,omitempty" dynamodbav:"appVersion,omitempty"`
	CurrentPage string `json:"currentPage,omitempty" dynamodbav:"currentPage,omitempty"`
	SessionID   string `json:"sessionId,omitempty" dynamodbav:"sessionId,omitempty"`
	Referrer    string `json:"referrer,omitempty" dynamodbav:"referrer,omitempty"`
	UserID      string `json:"userId,omitempty" dynamodbav:"userId,omitempty"`
}

// Feedback represents a user feedback entry
type Feedback struct {
	ID           string            `json:"id" dynamodbav:"id"`
	UserID       string            `json:"userId,omitempty" dynamodbav:"userId,omitempty"`
	Rating       int               `json:"rating" dynamodbav:"rating"`
	FeedbackText string            `json:"feedbackText" dynamodbav:"feedbackText"`
	Category     FeedbackCategory  `json:"category" dynamodbav:"category"`
	ContactEmail string            `json:"contactEmail,omitempty" dynamodbav:"contactEmail,omitempty"`
	DeviceInfo   *DeviceInfo       `json:"deviceInfo,omitempty" dynamodbav:"deviceInfo,omitempty"`
	CreatedAt    time.Time         `json:"createdAt" dynamodbav:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt" dynamodbav:"updatedAt"`
	Status       FeedbackStatus    `json:"status" dynamodbav:"status"`
	Metadata     *FeedbackMetadata `json:"metadata,omitempty" dynamodbav:"metadata,omitempty"`
}

// FeedbackSubmissionRequest represents the request payload for submitting feedback
type FeedbackSubmissionRequest struct {
	Rating       int               `json:"rating"`
	FeedbackText string            `json:"feedbackText"`
	Category     FeedbackCategory  `json:"category"`
	ContactEmail string            `json:"contactEmail,omitempty"`
	DeviceInfo   *DeviceInfo       `json:"deviceInfo,omitempty"`
	Metadata     *FeedbackMetadata `json:"metadata,omitempty"`
}

// FeedbackSubmissionResponse represents the response after submitting feedback
type FeedbackSubmissionResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// FeedbackListResponse represents the response for listing feedback
type FeedbackListResponse struct {
	Success  bool       `json:"success"`
	Feedback []Feedback `json:"feedback"`
	Count    int        `json:"count"`
	Error    string     `json:"error,omitempty"`
}

// FeedbackStatsResponse represents feedback statistics
type FeedbackStatsResponse struct {
	Success           bool                        `json:"success"`
	TotalFeedback     int                         `json:"totalFeedback"`
	AverageRating     float64                     `json:"averageRating"`
	CategoryBreakdown map[FeedbackCategory]int    `json:"categoryBreakdown"`
	StatusBreakdown   map[FeedbackStatus]int      `json:"statusBreakdown"`
	RecentFeedback    []Feedback                  `json:"recentFeedback"`
	Error             string                      `json:"error,omitempty"`
}

// NewFeedback creates a new feedback instance with validation
func NewFeedback(req FeedbackSubmissionRequest, userID string) (*Feedback, error) {
	if err := validateFeedbackRequest(req); err != nil {
		return nil, err
	}

	now := time.Now()
	feedback := &Feedback{
		ID:           uuid.New().String(),
		UserID:       userID,
		Rating:       req.Rating,
		FeedbackText: strings.TrimSpace(req.FeedbackText),
		Category:     req.Category,
		ContactEmail: strings.TrimSpace(req.ContactEmail),
		DeviceInfo:   req.DeviceInfo,
		CreatedAt:    now,
		UpdatedAt:    now,
		Status:       Submitted,
		Metadata:     req.Metadata,
	}

	return feedback, nil
}

// validateFeedbackRequest validates the feedback submission request
func validateFeedbackRequest(req FeedbackSubmissionRequest) error {
	// Validate rating
	if req.Rating < 1 || req.Rating > 5 {
		return errors.New("rating must be between 1 and 5")
	}

	// Validate feedback text
	feedbackText := strings.TrimSpace(req.FeedbackText)
	if len(feedbackText) == 0 {
		return errors.New("feedback text is required")
	}
	if len(feedbackText) < 10 {
		return errors.New("feedback text must be at least 10 characters")
	}
	if len(feedbackText) > 2000 {
		return errors.New("feedback text must be less than 2000 characters")
	}

	// Validate category
	if !isValidCategory(req.Category) {
		return errors.New("invalid feedback category")
	}

	// Validate email if provided
	if req.ContactEmail != "" && !isValidEmail(req.ContactEmail) {
		return errors.New("invalid email format")
	}

	return nil
}

// isValidCategory checks if the category is valid
func isValidCategory(category FeedbackCategory) bool {
	validCategories := []FeedbackCategory{
		BugReport, FeatureRequest, GeneralFeedback,
		UserExperience, Performance, Other,
	}

	for _, valid := range validCategories {
		if category == valid {
			return true
		}
	}
	return false
}

// isValidEmail validates email format
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	return emailRegex.MatchString(email)
}

// ToDynamoDBItem converts feedback to DynamoDB item
func (f *Feedback) ToDynamoDBItem() (map[string]*dynamodb.AttributeValue, error) {
	item, err := dynamodbattribute.MarshalMap(f)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal feedback to DynamoDB item: %w", err)
	}
	return item, nil
}

// FromDynamoDBItem creates feedback from DynamoDB item
func (f *Feedback) FromDynamoDBItem(item map[string]*dynamodb.AttributeValue) error {
	err := dynamodbattribute.UnmarshalMap(item, f)
	if err != nil {
		return fmt.Errorf("failed to unmarshal DynamoDB item to feedback: %w", err)
	}
	return nil
}

// UpdateStatus updates the feedback status
func (f *Feedback) UpdateStatus(status FeedbackStatus) {
	f.Status = status
	f.UpdatedAt = time.Now()
}

// GetCategoryDisplayName returns a human-readable category name
func (f *Feedback) GetCategoryDisplayName() string {
	switch f.Category {
	case BugReport:
		return "Bug Report"
	case FeatureRequest:
		return "Feature Request"
	case GeneralFeedback:
		return "General Feedback"
	case UserExperience:
		return "User Experience"
	case Performance:
		return "Performance"
	case Other:
		return "Other"
	default:
		return "Unknown"
	}
}

// GetStatusDisplayName returns a human-readable status name
func (f *Feedback) GetStatusDisplayName() string {
	switch f.Status {
	case Submitted:
		return "Submitted"
	case Reviewed:
		return "Reviewed"
	case InProgress:
		return "In Progress"
	case Resolved:
		return "Resolved"
	case Closed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// ToJSON converts feedback to JSON string
func (f *Feedback) ToJSON() (string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("failed to marshal feedback to JSON: %w", err)
	}
	return string(data), nil
}

// FromJSON creates feedback from JSON string
func (f *Feedback) FromJSON(data string) error {
	err := json.Unmarshal([]byte(data), f)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON to feedback: %w", err)
	}
	return nil
}

// Sanitize removes or escapes potentially harmful content
func (f *Feedback) Sanitize() {
	f.FeedbackText = sanitizeText(f.FeedbackText)
	if f.ContactEmail != "" {
		f.ContactEmail = strings.ToLower(strings.TrimSpace(f.ContactEmail))
	}
}

// sanitizeText removes potentially harmful content from text
func sanitizeText(text string) string {
	// Remove HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	text = htmlRegex.ReplaceAllString(text, "")
	
	// Remove script tags and content
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	text = scriptRegex.ReplaceAllString(text, "")
	
	// Trim whitespace
	text = strings.TrimSpace(text)
	
	return text
}

// GetTableName returns the DynamoDB table name for feedback
func GetFeedbackTableName() string {
	return "UserFeedback"
}

// GetGSIName returns the GSI name for querying by user ID
func GetUserFeedbackGSIName() string {
	return "UserIdIndex"
}

// GetCategoryGSIName returns the GSI name for querying by category
func GetCategoryGSIName() string {
	return "CategoryIndex"
}