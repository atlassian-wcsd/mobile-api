package feedback

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FeedbackHandler handles HTTP requests for feedback endpoints
type FeedbackHandler struct {
	store FeedbackStore
}

// NewFeedbackHandler creates a new feedback handler
func NewFeedbackHandler(store FeedbackStore) *FeedbackHandler {
	return &FeedbackHandler{
		store: store,
	}
}

// SubmitFeedbackHandler handles POST /api/feedback
func (h *FeedbackHandler) SubmitFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract user ID from request context or header
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		respondWithError(w, http.StatusBadRequest, "User ID is required")
		return
	}

	var req FeedbackSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate the feedback submission
	if err := ValidateFeedbackSubmission(req); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Create feedback object
	feedback := Feedback{
		ID:          generateFeedbackID(),
		UserID:      userID,
		Message:     req.Message,
		Rating:      req.Rating,
		ContactInfo: req.ContactInfo,
		Category:    setDefaultCategory(req.Category),
		CreatedAt:   time.Now(),
		Status:      "new",
		Metadata: map[string]interface{}{
			"userAgent": r.Header.Get("User-Agent"),
		},
	}

	// Sanitize feedback
	SanitizeFeedback(&feedback)

	// Store feedback
	if err := h.store.SubmitFeedback(feedback); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to submit feedback")
		return
	}

	response := FeedbackSubmissionResponse{
		Success:    true,
		FeedbackID: feedback.ID,
		Message:    "Feedback submitted successfully",
	}

	respondWithJSON(w, http.StatusCreated, response)
}

// GetFeedbackHandler handles GET /api/feedback/:id
func (h *FeedbackHandler) GetFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract feedback ID from URL path
	feedbackID := extractIDFromPath(r.URL.Path, "/api/feedback/")
	if feedbackID == "" {
		respondWithError(w, http.StatusBadRequest, "Feedback ID is required")
		return
	}

	feedback, err := h.store.GetFeedback(feedbackID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Feedback not found")
		return
	}

	respondWithJSON(w, http.StatusOK, feedback)
}

// GetUserFeedbackHandler handles GET /api/user/:userId/feedback
func (h *FeedbackHandler) GetUserFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := extractIDFromPath(r.URL.Path, "/api/user/")
	if userID == "" {
		respondWithError(w, http.StatusBadRequest, "User ID is required")
		return
	}

	feedbacks, err := h.store.GetUserFeedback(userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve feedback")
		return
	}

	respondWithJSON(w, http.StatusOK, feedbacks)
}

// GetAllFeedbackHandler handles GET /api/admin/feedback
func (h *FeedbackHandler) GetAllFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Optional status filter from query parameter
	status := r.URL.Query().Get("status")

	feedbacks, err := h.store.GetAllFeedback(status)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve feedback")
		return
	}

	respondWithJSON(w, http.StatusOK, feedbacks)
}

// GetFeedbackByCategoryHandler handles GET /api/feedback/category/:category
func (h *FeedbackHandler) GetFeedbackByCategoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract category from URL path
	category := extractIDFromPath(r.URL.Path, "/api/feedback/category/")
	if category == "" {
		respondWithError(w, http.StatusBadRequest, "Category is required")
		return
	}

	feedbacks, err := h.store.GetFeedbackByCategory(category)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve feedback")
		return
	}

	respondWithJSON(w, http.StatusOK, feedbacks)
}

// UpdateFeedbackStatusHandler handles PUT /api/feedback/:id/status
func (h *FeedbackHandler) UpdateFeedbackStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract feedback ID from URL path
	feedbackID := extractIDFromPath(r.URL.Path, "/api/feedback/")
	if feedbackID == "" {
		respondWithError(w, http.StatusBadRequest, "Feedback ID is required")
		return
	}

	var req struct {
		Status        string `json:"status"`
		InternalNotes string `json:"internalNotes,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Status == "" {
		respondWithError(w, http.StatusBadRequest, "Status is required")
		return
	}

	// Validate status value
	validStatuses := map[string]bool{"new": true, "reviewed": true, "resolved": true, "archived": true}
	if !validStatuses[req.Status] {
		respondWithError(w, http.StatusBadRequest, "Invalid status value")
		return
	}

	feedback, err := h.store.UpdateFeedbackStatus(feedbackID, req.Status, req.InternalNotes)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Feedback not found")
		return
	}

	respondWithJSON(w, http.StatusOK, feedback)
}

// GetStatisticsHandler handles GET /api/admin/feedback/statistics
func (h *FeedbackHandler) GetStatisticsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	stats := h.store.GetStatistics()
	respondWithJSON(w, http.StatusOK, stats)
}

// Helper functions

func generateFeedbackID() string {
	return "fb_" + uuid.New().String()
}

func setDefaultCategory(category string) string {
	if category == "" {
		return "general"
	}
	validCategories := map[string]bool{
		"bug":             true,
		"feature-request": true,
		"general":         true,
		"other":           true,
	}
	if validCategories[category] {
		return category
	}
	return "general"
}

func extractIDFromPath(path, prefix string) string {
	if strings.HasPrefix(path, prefix) {
		id := strings.TrimPrefix(path, prefix)
		// Remove any trailing path
		if idx := strings.Index(id, "/"); idx != -1 {
			id = id[:idx]
		}
		return id
	}
	return ""
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	errorResponse := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	respondWithJSON(w, code, errorResponse)
}
