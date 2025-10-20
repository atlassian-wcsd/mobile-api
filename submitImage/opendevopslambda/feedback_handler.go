package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"submit-image/models"
	"submit-image/services"
)

// FeedbackHandler handles feedback-related HTTP requests
type FeedbackHandler struct {
	feedbackService *services.FeedbackService
}

// NewFeedbackHandler creates a new feedback handler
func NewFeedbackHandler(dynamoDB dynamodbiface.DynamoDBAPI) *FeedbackHandler {
	return &FeedbackHandler{
		feedbackService: services.NewFeedbackService(dynamoDB),
	}
}

// HandleFeedbackRequest routes feedback requests to appropriate handlers
func (h *FeedbackHandler) HandleFeedbackRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	path := request.Path
	method := request.HTTPMethod

	log.Printf("Handling feedback request: %s %s", method, path)

	// Enable CORS for all feedback endpoints
	corsHeaders := map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
		"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
	}

	// Handle OPTIONS requests for CORS
	if method == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Headers:    corsHeaders,
			Body:       "",
		}, nil
	}

	switch {
	case path == "/feedback" && method == "POST":
		return h.handleSubmitFeedback(ctx, request, corsHeaders)
	case strings.HasPrefix(path, "/feedback/") && method == "GET":
		// Extract feedback ID from path
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			feedbackID := parts[2]
			return h.handleGetFeedback(ctx, feedbackID, corsHeaders)
		}
		return h.createErrorResponse(400, "Invalid feedback ID", corsHeaders), nil
	case path == "/feedback/user" && method == "GET":
		return h.handleGetUserFeedback(ctx, request, corsHeaders)
	case path == "/feedback/admin/all" && method == "GET":
		return h.handleGetAllFeedback(ctx, request, corsHeaders)
	case path == "/feedback/admin/stats" && method == "GET":
		return h.handleGetFeedbackStats(ctx, corsHeaders)
	default:
		return h.createErrorResponse(404, "Endpoint not found", corsHeaders), nil
	}
}

// handleSubmitFeedback handles feedback submission
func (h *FeedbackHandler) handleSubmitFeedback(ctx context.Context, request events.APIGatewayProxyRequest, corsHeaders map[string]string) (events.APIGatewayProxyResponse, error) {
	// Parse request body
	var feedbackReq models.FeedbackSubmissionRequest
	if err := json.Unmarshal([]byte(request.Body), &feedbackReq); err != nil {
		log.Printf("Error parsing feedback request: %v", err)
		return h.createErrorResponse(400, "Invalid request body", corsHeaders), nil
	}

	// Get user agent from headers
	userAgent := request.Headers["User-Agent"]
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// Submit feedback
	response, err := h.feedbackService.SubmitFeedback(&feedbackReq, userAgent)
	if err != nil {
		log.Printf("Error submitting feedback: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	statusCode := 200
	if !response.Success {
		statusCode = 400
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}, nil
}

// handleGetFeedback handles getting feedback by ID
func (h *FeedbackHandler) handleGetFeedback(ctx context.Context, feedbackID string, corsHeaders map[string]string) (events.APIGatewayProxyResponse, error) {
	feedback, err := h.feedbackService.GetFeedback(feedbackID)
	if err != nil {
		log.Printf("Error getting feedback: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	if feedback == nil {
		return h.createErrorResponse(404, "Feedback not found", corsHeaders), nil
	}

	responseBody, err := json.Marshal(feedback)
	if err != nil {
		log.Printf("Error marshaling feedback: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}, nil
}

// handleGetUserFeedback handles getting feedback for a specific user
func (h *FeedbackHandler) handleGetUserFeedback(ctx context.Context, request events.APIGatewayProxyRequest, corsHeaders map[string]string) (events.APIGatewayProxyResponse, error) {
	// Get user ID from query parameters
	userID := request.QueryStringParameters["userId"]
	if userID == "" {
		return h.createErrorResponse(400, "userId parameter is required", corsHeaders), nil
	}

	// TODO: Add authentication check here to ensure user can only access their own feedback
	// For now, we'll allow any request

	feedbackList, err := h.feedbackService.GetUserFeedback(userID)
	if err != nil {
		log.Printf("Error getting user feedback: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	response := models.FeedbackListResponse{
		Success:  true,
		Feedback: feedbackList,
		Count:    len(feedbackList),
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling feedback list: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}, nil
}

// handleGetAllFeedback handles getting all feedback (admin endpoint)
func (h *FeedbackHandler) handleGetAllFeedback(ctx context.Context, request events.APIGatewayProxyRequest, corsHeaders map[string]string) (events.APIGatewayProxyResponse, error) {
	// TODO: Add admin authentication check here
	// For now, we'll allow any request

	// Get limit from query parameters
	limitStr := request.QueryStringParameters["limit"]
	limit := 100 // Default limit
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	feedbackList, err := h.feedbackService.GetAllFeedback(limit)
	if err != nil {
		log.Printf("Error getting all feedback: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	response := models.FeedbackListResponse{
		Success:  true,
		Feedback: feedbackList,
		Count:    len(feedbackList),
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling feedback list: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}, nil
}

// handleGetFeedbackStats handles getting feedback statistics
func (h *FeedbackHandler) handleGetFeedbackStats(ctx context.Context, corsHeaders map[string]string) (events.APIGatewayProxyResponse, error) {
	// TODO: Add admin authentication check here

	stats, err := h.feedbackService.GetFeedbackStats()
	if err != nil {
		log.Printf("Error getting feedback stats: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	responseBody, err := json.Marshal(map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
	if err != nil {
		log.Printf("Error marshaling stats: %v", err)
		return h.createErrorResponse(500, "Internal server error", corsHeaders), err
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}, nil
}

// createErrorResponse creates a standardized error response
func (h *FeedbackHandler) createErrorResponse(statusCode int, message string, corsHeaders map[string]string) events.APIGatewayProxyResponse {
	errorResponse := map[string]interface{}{
		"success": false,
		"error":   message,
	}

	responseBody, _ := json.Marshal(errorResponse)

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    corsHeaders,
		Body:       string(responseBody),
	}
}