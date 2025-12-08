package feedback

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Feedback represents user feedback
type Feedback struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"userId"`
	Message     string                 `json:"message"`
	Rating      int                    `json:"rating"`
	ContactInfo string                 `json:"contactInfo,omitempty"`
	Category    string                 `json:"category"`
	CreatedAt   time.Time              `json:"createdAt"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
	InternalNotes string                `json:"internalNotes,omitempty"`
}

// FeedbackSubmissionRequest is the request payload for submitting feedback
type FeedbackSubmissionRequest struct {
	Message     string `json:"message"`
	Rating      int    `json:"rating"`
	ContactInfo string `json:"contactInfo,omitempty"`
	Category    string `json:"category,omitempty"`
}

// FeedbackSubmissionResponse is the response for feedback submission
type FeedbackSubmissionResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// FeedbackStore is an interface for storing and retrieving feedback
type FeedbackStore interface {
	SubmitFeedback(feedback Feedback) error
	GetFeedback(feedbackID string) (*Feedback, error)
	GetUserFeedback(userID string) ([]Feedback, error)
	GetAllFeedback(status string) ([]Feedback, error)
	GetFeedbackByCategory(category string) ([]Feedback, error)
	UpdateFeedbackStatus(feedbackID, status, internalNotes string) (*Feedback, error)
	DeleteFeedback(feedbackID string) error
	GetStatistics() map[string]interface{}
}

// InMemoryFeedbackStore provides in-memory storage for feedback
type InMemoryFeedbackStore struct {
	mu        sync.RWMutex
	feedbacks map[string]Feedback
}

// NewInMemoryFeedbackStore creates a new in-memory feedback store
func NewInMemoryFeedbackStore() *InMemoryFeedbackStore {
	return &InMemoryFeedbackStore{
		feedbacks: make(map[string]Feedback),
	}
}

// SubmitFeedback stores new feedback
func (s *InMemoryFeedbackStore) SubmitFeedback(feedback Feedback) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if feedback.ID == "" {
		return errors.New("feedback ID is required")
	}
	if feedback.UserID == "" {
		return errors.New("user ID is required")
	}
	if feedback.Message == "" {
		return errors.New("feedback message is required")
	}
	if feedback.Rating < 1 || feedback.Rating > 5 {
		return errors.New("rating must be between 1 and 5")
	}

	s.feedbacks[feedback.ID] = feedback
	return nil
}

// GetFeedback retrieves feedback by ID
func (s *InMemoryFeedbackStore) GetFeedback(feedbackID string) (*Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	feedback, exists := s.feedbacks[feedbackID]
	if !exists {
		return nil, errors.New("feedback not found")
	}
	return &feedback, nil
}

// GetUserFeedback retrieves all feedback from a user
func (s *InMemoryFeedbackStore) GetUserFeedback(userID string) ([]Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Feedback
	for _, feedback := range s.feedbacks {
		if feedback.UserID == userID {
			results = append(results, feedback)
		}
	}

	// Sort by creation time, newest first
	sortByCreatedAt(results)
	return results, nil
}

// GetAllFeedback retrieves all feedback, optionally filtered by status
func (s *InMemoryFeedbackStore) GetAllFeedback(status string) ([]Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Feedback
	for _, feedback := range s.feedbacks {
		if status == "" || feedback.Status == status {
			results = append(results, feedback)
		}
	}

	// Sort by creation time, newest first
	sortByCreatedAt(results)
	return results, nil
}

// GetFeedbackByCategory retrieves feedback by category
func (s *InMemoryFeedbackStore) GetFeedbackByCategory(category string) ([]Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Feedback
	for _, feedback := range s.feedbacks {
		if feedback.Category == category {
			results = append(results, feedback)
		}
	}

	// Sort by creation time, newest first
	sortByCreatedAt(results)
	return results, nil
}

// UpdateFeedbackStatus updates the status and internal notes of feedback
func (s *InMemoryFeedbackStore) UpdateFeedbackStatus(feedbackID, status, internalNotes string) (*Feedback, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	feedback, exists := s.feedbacks[feedbackID]
	if !exists {
		return nil, errors.New("feedback not found")
	}

	feedback.Status = status
	if internalNotes != "" {
		feedback.InternalNotes = internalNotes
	}

	s.feedbacks[feedbackID] = feedback
	return &feedback, nil
}

// DeleteFeedback removes feedback
func (s *InMemoryFeedbackStore) DeleteFeedback(feedbackID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.feedbacks[feedbackID]; !exists {
		return errors.New("feedback not found")
	}

	delete(s.feedbacks, feedbackID)
	return nil
}

// GetStatistics returns feedback statistics
func (s *InMemoryFeedbackStore) GetStatistics() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"totalFeedback":      0,
		"averageRating":      0.0,
		"feedbackByCategory": make(map[string]int),
		"feedbackByStatus":   make(map[string]int),
	}

	if len(s.feedbacks) == 0 {
		return stats
	}

	totalRating := 0
	categoryCount := make(map[string]int)
	statusCount := make(map[string]int)

	for _, feedback := range s.feedbacks {
		totalRating += feedback.Rating
		categoryCount[feedback.Category]++
		statusCount[feedback.Status]++
	}

	stats["totalFeedback"] = len(s.feedbacks)
	stats["averageRating"] = float64(totalRating) / float64(len(s.feedbacks))
	stats["feedbackByCategory"] = categoryCount
	stats["feedbackByStatus"] = statusCount

	return stats
}

// Helper function to sort feedbacks by creation time (newest first)
func sortByCreatedAt(feedbacks []Feedback) {
	// Simple bubble sort (can be optimized with sort package if needed)
	for i := 0; i < len(feedbacks); i++ {
		for j := i + 1; j < len(feedbacks); j++ {
			if feedbacks[i].CreatedAt.Before(feedbacks[j].CreatedAt) {
				feedbacks[i], feedbacks[j] = feedbacks[j], feedbacks[i]
			}
		}
	}
}

// ValidateFeedbackSubmission validates feedback before storage
func ValidateFeedbackSubmission(req FeedbackSubmissionRequest) error {
	if req.Message == "" {
		return errors.New("feedback message is required")
	}
	if len(req.Message) > 5000 {
		return errors.New("feedback message cannot exceed 5000 characters")
	}
	if req.Rating < 1 || req.Rating > 5 {
		return errors.New("rating must be an integer between 1 and 5")
	}
	return nil
}

// SanitizeFeedback sanitizes feedback data (removes potentially harmful content)
func SanitizeFeedback(feedback *Feedback) {
	// Basic sanitization - in production, use a proper HTML sanitizer
	// For now, we're just ensuring the data is properly trimmed
	feedback.Message = truncateString(feedback.Message, 5000)
	feedback.ContactInfo = truncateString(feedback.ContactInfo, 255)
}

// Helper function to truncate strings
func truncateString(s string, maxLength int) string {
	if len(s) > maxLength {
		return s[:maxLength]
	}
	return s
}

// MarshalJSON implements custom JSON marshaling for Feedback
func (f Feedback) MarshalJSON() ([]byte, error) {
	type Alias Feedback
	return json.Marshal(&struct {
		CreatedAt string `json:"createdAt"`
		*Alias
	}{
		CreatedAt: f.CreatedAt.Format(time.RFC3339),
		Alias:     (*Alias)(&f),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for Feedback
func (f *Feedback) UnmarshalJSON(data []byte) error {
	type Alias Feedback
	aux := &struct {
		CreatedAt string `json:"createdAt"`
		*Alias
	}{
		Alias: (*Alias)(f),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.CreatedAt != "" {
		t, err := time.Parse(time.RFC3339, aux.CreatedAt)
		if err != nil {
			return err
		}
		f.CreatedAt = t
	}
	return nil
}
