package feedback

import (
	"testing"
	"time"
)

func TestNewInMemoryFeedbackStore(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	if store == nil {
		t.Fatal("Expected store to be created")
	}
}

func TestSubmitFeedback(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedback := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Great app!",
		Rating:    5,
		Category:  "general",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	err := store.SubmitFeedback(feedback)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify feedback was stored
	retrieved, err := store.GetFeedback(feedback.ID)
	if err != nil {
		t.Fatalf("Expected no error retrieving feedback, got %v", err)
	}
	if retrieved.Message != feedback.Message {
		t.Errorf("Expected message '%s', got '%s'", feedback.Message, retrieved.Message)
	}
}

func TestSubmitFeedbackValidation(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	tests := []struct {
		name      string
		feedback  Feedback
		expectErr bool
	}{
		{
			name: "Valid feedback",
			feedback: Feedback{
				ID:        "fb_test_1",
				UserID:    "user_123",
				Message:   "Test message",
				Rating:    3,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: false,
		},
		{
			name: "Missing ID",
			feedback: Feedback{
				UserID:    "user_123",
				Message:   "Test message",
				Rating:    3,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: true,
		},
		{
			name: "Missing UserID",
			feedback: Feedback{
				ID:        "fb_test_1",
				Message:   "Test message",
				Rating:    3,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: true,
		},
		{
			name: "Missing Message",
			feedback: Feedback{
				ID:        "fb_test_1",
				UserID:    "user_123",
				Rating:    3,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: true,
		},
		{
			name: "Invalid Rating (too low)",
			feedback: Feedback{
				ID:        "fb_test_1",
				UserID:    "user_123",
				Message:   "Test message",
				Rating:    0,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: true,
		},
		{
			name: "Invalid Rating (too high)",
			feedback: Feedback{
				ID:        "fb_test_1",
				UserID:    "user_123",
				Message:   "Test message",
				Rating:    6,
				Category:  "general",
				CreatedAt: time.Now(),
				Status:    "new",
				Metadata:  make(map[string]interface{}),
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := store.SubmitFeedback(test.feedback)
			if (err != nil) != test.expectErr {
				t.Errorf("Expected error: %v, got: %v", test.expectErr, err != nil)
			}
		})
	}
}

func TestGetFeedback(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedback := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Test feedback",
		Rating:    4,
		Category:  "feature-request",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	store.SubmitFeedback(feedback)

	retrieved, err := store.GetFeedback("fb_test_1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrieved.ID != feedback.ID {
		t.Errorf("Expected ID '%s', got '%s'", feedback.ID, retrieved.ID)
	}
}

func TestGetFeedbackNotFound(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	_, err := store.GetFeedback("nonexistent_id")
	if err == nil {
		t.Fatal("Expected error for nonexistent feedback")
	}
}

func TestGetUserFeedback(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	// Submit multiple feedbacks
	feedback1 := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Feedback 1",
		Rating:    3,
		Category:  "general",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	feedback2 := Feedback{
		ID:        "fb_test_2",
		UserID:    "user_123",
		Message:   "Feedback 2",
		Rating:    4,
		Category:  "bug",
		CreatedAt: time.Now().Add(time.Hour),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	feedback3 := Feedback{
		ID:        "fb_test_3",
		UserID:    "user_456",
		Message:   "Feedback 3",
		Rating:    5,
		Category:  "feature-request",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	store.SubmitFeedback(feedback1)
	store.SubmitFeedback(feedback2)
	store.SubmitFeedback(feedback3)

	userFeedback, err := store.GetUserFeedback("user_123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(userFeedback) != 2 {
		t.Errorf("Expected 2 feedbacks, got %d", len(userFeedback))
	}
}

func TestGetFeedbackByCategory(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedbacks := []Feedback{
		{
			ID:        "fb_test_1",
			UserID:    "user_123",
			Message:   "Bug report",
			Rating:    1,
			Category:  "bug",
			CreatedAt: time.Now(),
			Status:    "new",
			Metadata:  make(map[string]interface{}),
		},
		{
			ID:        "fb_test_2",
			UserID:    "user_123",
			Message:   "Feature request",
			Rating:    4,
			Category:  "feature-request",
			CreatedAt: time.Now(),
			Status:    "new",
			Metadata:  make(map[string]interface{}),
		},
		{
			ID:        "fb_test_3",
			UserID:    "user_123",
			Message:   "Another bug",
			Rating:    2,
			Category:  "bug",
			CreatedAt: time.Now(),
			Status:    "new",
			Metadata:  make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	bugFeedbacks, err := store.GetFeedbackByCategory("bug")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(bugFeedbacks) != 2 {
		t.Errorf("Expected 2 bug feedbacks, got %d", len(bugFeedbacks))
	}
}

func TestUpdateFeedbackStatus(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedback := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Test",
		Rating:    3,
		Category:  "general",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	store.SubmitFeedback(feedback)

	updated, err := store.UpdateFeedbackStatus("fb_test_1", "reviewed", "Internal note added")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if updated.Status != "reviewed" {
		t.Errorf("Expected status 'reviewed', got '%s'", updated.Status)
	}
	if updated.InternalNotes != "Internal note added" {
		t.Errorf("Expected internal notes 'Internal note added', got '%s'", updated.InternalNotes)
	}
}

func TestDeleteFeedback(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedback := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Test",
		Rating:    3,
		Category:  "general",
		CreatedAt: time.Now(),
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}

	store.SubmitFeedback(feedback)

	err := store.DeleteFeedback("fb_test_1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = store.GetFeedback("fb_test_1")
	if err == nil {
		t.Fatal("Expected error retrieving deleted feedback")
	}
}

func TestGetStatistics(t *testing.T) {
	store := NewInMemoryFeedbackStore()

	feedbacks := []Feedback{
		{
			ID:        "fb_test_1",
			UserID:    "user_123",
			Message:   "Good",
			Rating:    5,
			Category:  "general",
			CreatedAt: time.Now(),
			Status:    "new",
			Metadata:  make(map[string]interface{}),
		},
		{
			ID:        "fb_test_2",
			UserID:    "user_123",
			Message:   "Bad",
			Rating:    1,
			Category:  "bug",
			CreatedAt: time.Now(),
			Status:    "reviewed",
			Metadata:  make(map[string]interface{}),
		},
		{
			ID:        "fb_test_3",
			UserID:    "user_456",
			Message:   "Average",
			Rating:    3,
			Category:  "feature-request",
			CreatedAt: time.Now(),
			Status:    "new",
			Metadata:  make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	stats := store.GetStatistics()

	if stats["totalFeedback"] != 3 {
		t.Errorf("Expected total feedback 3, got %v", stats["totalFeedback"])
	}

	expectedAverage := 3.0 // (5 + 1 + 3) / 3
	if avgRating, ok := stats["averageRating"].(float64); ok {
		if avgRating != expectedAverage {
			t.Errorf("Expected average rating %.1f, got %.1f", expectedAverage, avgRating)
		}
	} else {
		t.Error("Average rating not a float")
	}
}

func TestValidateFeedbackSubmission(t *testing.T) {
	tests := []struct {
		name      string
		request   FeedbackSubmissionRequest
		expectErr bool
		errMsg    string
	}{
		{
			name: "Valid request",
			request: FeedbackSubmissionRequest{
				Message: "Good feedback",
				Rating:  4,
			},
			expectErr: false,
		},
		{
			name: "Empty message",
			request: FeedbackSubmissionRequest{
				Message: "",
				Rating:  4,
			},
			expectErr: true,
			errMsg:    "feedback message is required",
		},
		{
			name: "Message too long",
			request: FeedbackSubmissionRequest{
				Message: string(make([]byte, 5001)),
				Rating:  4,
			},
			expectErr: true,
			errMsg:    "cannot exceed 5000 characters",
		},
		{
			name: "Invalid rating (too low)",
			request: FeedbackSubmissionRequest{
				Message: "Test",
				Rating:  0,
			},
			expectErr: true,
			errMsg:    "between 1 and 5",
		},
		{
			name: "Invalid rating (too high)",
			request: FeedbackSubmissionRequest{
				Message: "Test",
				Rating:  6,
			},
			expectErr: true,
			errMsg:    "between 1 and 5",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateFeedbackSubmission(test.request)
			if (err != nil) != test.expectErr {
				t.Errorf("Expected error: %v, got error: %v", test.expectErr, err != nil)
			}
			if test.expectErr && test.errMsg != "" && (err == nil || !contains(err.Error(), test.errMsg)) {
				t.Errorf("Expected error containing '%s', got '%v'", test.errMsg, err)
			}
		})
	}
}

func TestSanitizeFeedback(t *testing.T) {
	feedback := &Feedback{
		ID:      "fb_test_1",
		UserID:  "user_123",
		Message: "Test message",
		ContactInfo: "test@example.com",
		Metadata: make(map[string]interface{}),
	}

	SanitizeFeedback(feedback)

	if feedback.Message != "Test message" {
		t.Errorf("Message was altered: %s", feedback.Message)
	}

	// Test with oversized message
	longMessage := string(make([]byte, 6000))
	feedback.Message = longMessage
	SanitizeFeedback(feedback)

	if len(feedback.Message) > 5000 {
		t.Errorf("Message not truncated: length %d", len(feedback.Message))
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
