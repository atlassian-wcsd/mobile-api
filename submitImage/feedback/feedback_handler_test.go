package feedback

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitFeedbackHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	tests := []struct {
		name           string
		method         string
		body           FeedbackSubmissionRequest
		userID         string
		expectedStatus int
		shouldSucceed  bool
	}{
		{
			name:   "Valid feedback submission",
			method: http.MethodPost,
			body: FeedbackSubmissionRequest{
				Message:  "Great app!",
				Rating:   5,
				Category: "general",
			},
			userID:         "user_123",
			expectedStatus: http.StatusCreated,
			shouldSucceed:  true,
		},
		{
			name:   "Missing message",
			method: http.MethodPost,
			body: FeedbackSubmissionRequest{
				Rating: 4,
			},
			userID:         "user_123",
			expectedStatus: http.StatusBadRequest,
			shouldSucceed:  false,
		},
		{
			name:   "Invalid rating",
			method: http.MethodPost,
			body: FeedbackSubmissionRequest{
				Message: "Test",
				Rating:  6,
			},
			userID:         "user_123",
			expectedStatus: http.StatusBadRequest,
			shouldSucceed:  false,
		},
		{
			name:   "Missing user ID",
			method: http.MethodPost,
			body: FeedbackSubmissionRequest{
				Message: "Test",
				Rating:  3,
			},
			userID:         "",
			expectedStatus: http.StatusBadRequest,
			shouldSucceed:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(test.body)
			req := httptest.NewRequest(http.MethodPost, "/api/feedback", bytes.NewReader(bodyBytes))
			req.Header.Set("X-User-ID", test.userID)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.SubmitFeedbackHandler(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)

			if test.shouldSucceed && !response["success"].(bool) {
				t.Error("Expected successful response")
			}
		})
	}
}

func TestGetFeedbackHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedback
	feedback := Feedback{
		ID:        "fb_test_1",
		UserID:    "user_123",
		Message:   "Test feedback",
		Rating:    4,
		Category:  "general",
		Status:    "new",
		Metadata:  make(map[string]interface{}),
	}
	store.SubmitFeedback(feedback)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		shouldExist    bool
	}{
		{
			name:           "Get existing feedback",
			method:         http.MethodGet,
			path:           "/api/feedback/fb_test_1",
			expectedStatus: http.StatusOK,
			shouldExist:    true,
		},
		{
			name:           "Get nonexistent feedback",
			method:         http.MethodGet,
			path:           "/api/feedback/nonexistent",
			expectedStatus: http.StatusNotFound,
			shouldExist:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			w := httptest.NewRecorder()
			handler.GetFeedbackHandler(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}
		})
	}
}

func TestGetUserFeedbackHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedbacks
	feedbacks := []Feedback{
		{
			ID:       "fb_1",
			UserID:   "user_123",
			Message:  "Feedback 1",
			Rating:   3,
			Category: "general",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       "fb_2",
			UserID:   "user_123",
			Message:  "Feedback 2",
			Rating:   4,
			Category: "bug",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/user/user_123/feedback", nil)
	w := httptest.NewRecorder()
	handler.GetUserFeedbackHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response []Feedback
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response) != 2 {
		t.Errorf("Expected 2 feedbacks, got %d", len(response))
	}
}

func TestGetAllFeedbackHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedbacks with different statuses
	feedbacks := []Feedback{
		{
			ID:       "fb_1",
			UserID:   "user_123",
			Message:  "New feedback",
			Rating:   3,
			Category: "general",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       "fb_2",
			UserID:   "user_456",
			Message:  "Reviewed feedback",
			Rating:   4,
			Category: "bug",
			Status:   "reviewed",
			Metadata: make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	tests := []struct {
		name           string
		path           string
		expectedCount  int
		expectedStatus int
	}{
		{
			name:           "Get all feedback",
			path:           "/api/admin/feedback",
			expectedCount:  2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get feedback by status",
			path:           "/api/admin/feedback?status=new",
			expectedCount:  1,
			expectedStatus: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			w := httptest.NewRecorder()
			handler.GetAllFeedbackHandler(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}

			var response []Feedback
			json.Unmarshal(w.Body.Bytes(), &response)

			if len(response) != test.expectedCount {
				t.Errorf("Expected %d feedbacks, got %d", test.expectedCount, len(response))
			}
		})
	}
}

func TestGetFeedbackByCategoryHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedbacks
	feedbacks := []Feedback{
		{
			ID:       "fb_1",
			UserID:   "user_123",
			Message:  "Bug report",
			Rating:   1,
			Category: "bug",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       "fb_2",
			UserID:   "user_456",
			Message:  "Feature request",
			Rating:   4,
			Category: "feature-request",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/feedback/category/bug", nil)
	w := httptest.NewRecorder()
	handler.GetFeedbackByCategoryHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response []Feedback
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response) != 1 {
		t.Errorf("Expected 1 bug feedback, got %d", len(response))
	}

	if response[0].Category != "bug" {
		t.Errorf("Expected category 'bug', got '%s'", response[0].Category)
	}
}

func TestUpdateFeedbackStatusHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedback
	feedback := Feedback{
		ID:       "fb_test_1",
		UserID:   "user_123",
		Message:  "Test feedback",
		Rating:   4,
		Category: "general",
		Status:   "new",
		Metadata: make(map[string]interface{}),
	}
	store.SubmitFeedback(feedback)

	updateData := map[string]string{
		"status":          "reviewed",
		"internalNotes": "Acknowledged and reviewed",
	}

	bodyBytes, _ := json.Marshal(updateData)
	req := httptest.NewRequest(http.MethodPut, "/api/feedback/fb_test_1/status", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.UpdateFeedbackStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response Feedback
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Status != "reviewed" {
		t.Errorf("Expected status 'reviewed', got '%s'", response.Status)
	}
}

func TestGetStatisticsHandler(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	// Add test feedbacks
	feedbacks := []Feedback{
		{
			ID:       "fb_1",
			UserID:   "user_123",
			Message:  "Good",
			Rating:   5,
			Category: "general",
			Status:   "new",
			Metadata: make(map[string]interface{}),
		},
		{
			ID:       "fb_2",
			UserID:   "user_456",
			Message:  "Bad",
			Rating:   1,
			Category: "bug",
			Status:   "reviewed",
			Metadata: make(map[string]interface{}),
		},
	}

	for _, fb := range feedbacks {
		store.SubmitFeedback(fb)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/feedback/statistics", nil)
	w := httptest.NewRecorder()
	handler.GetStatisticsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["totalFeedback"] != float64(2) {
		t.Errorf("Expected total feedback 2, got %v", response["totalFeedback"])
	}
}

func TestInvalidHTTPMethods(t *testing.T) {
	store := NewInMemoryFeedbackStore()
	handler := NewFeedbackHandler(store)

	tests := []struct {
		name           string
		method         string
		path           string
		handler        func(http.ResponseWriter, *http.Request)
		expectedStatus int
	}{
		{
			name:           "GET on POST endpoint",
			method:         http.MethodGet,
			path:           "/api/feedback",
			handler:        handler.SubmitFeedbackHandler,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "DELETE on PUT endpoint",
			method:         http.MethodDelete,
			path:           "/api/feedback/fb_1/status",
			handler:        handler.UpdateFeedbackStatusHandler,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			w := httptest.NewRecorder()
			test.handler(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}
		})
	}
}
