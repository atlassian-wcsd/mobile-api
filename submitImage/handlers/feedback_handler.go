package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// HandleFeedbackSubmission handles POST /feedback
func (fh *FeedbackHandler) HandleFeedbackSubmission(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback submission")

	// Parse request body
	var req models.FeedbackSubmissionRequest
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		log.Printf("Failed to parse request body: %v", err)
		return createErrorResponse(400, "Invalid request body"), nil
	}

	// Extract user ID from context or headers (if authenticated)
	userID := extractUserID(request)

	// Submit feedback
	response, err := fh.feedbackService.SubmitFeedback(req, userID)
	if err != nil {
		log.Printf("Failed to submit feedback: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	statusCode := 200
	if !response.Success {
		statusCode = 400
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

// HandleFeedbackHistory handles GET /feedback/history
func (fh *FeedbackHandler) HandleFeedbackHistory(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback history request")

	// Extract user ID from authentication
	userID := extractUserID(request)
	if userID == "" {
		return createErrorResponse(401, "Authentication required"), nil
	}

	// Parse limit parameter
	limit := 20
	if limitStr, exists := request.QueryStringParameters["limit"]; exists {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Get feedback history
	response, err := fh.feedbackService.GetFeedbackByUser(userID, limit)
	if err != nil {
		log.Printf("Failed to get feedback history: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

// HandleFeedbackStats handles GET /feedback/stats
func (fh *FeedbackHandler) HandleFeedbackStats(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback stats request")

	// This endpoint requires admin authentication
	// For now, we'll check for a valid auth token
	userID := extractUserID(request)
	if userID == "" {
		return createErrorResponse(401, "Authentication required"), nil
	}

	// Get feedback statistics
	response, err := fh.feedbackService.GetFeedbackStats()
	if err != nil {
		log.Printf("Failed to get feedback stats: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

// HandleFeedbackByCategory handles GET /feedback/category/{category}
func (fh *FeedbackHandler) HandleFeedbackByCategory(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback by category request")

	// Extract category from path parameters
	category, exists := request.PathParameters["category"]
	if !exists {
		return createErrorResponse(400, "Category parameter is required"), nil
	}

	// Validate category
	feedbackCategory := models.FeedbackCategory(category)
	if !isValidCategory(feedbackCategory) {
		return createErrorResponse(400, "Invalid category"), nil
	}

	// Parse limit parameter
	limit := 50
	if limitStr, exists := request.QueryStringParameters["limit"]; exists {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Get feedback by category
	response, err := fh.feedbackService.GetFeedbackByCategory(feedbackCategory, limit)
	if err != nil {
		log.Printf("Failed to get feedback by category: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	// Return response
	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return createErrorResponse(500, "Internal server error"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

// HandleFeedbackOptions handles OPTIONS requests for CORS
func (fh *FeedbackHandler) HandleFeedbackOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    getCORSHeaders(),
		Body:       "",
	}, nil
}

// HandleHealthCheck handles GET /feedback/health
func (fh *FeedbackHandler) HandleHealthCheck(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	healthResponse := map[string]interface{}{
		"status":    "healthy",
		"service":   "feedback",
		"timestamp": fmt.Sprintf("%d", request.RequestContext.RequestTimeEpoch),
	}

	responseBody, err := json.Marshal(healthResponse)
	if err != nil {
		return createErrorResponse(500, "Internal server error"), nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

// Helper functions

// extractUserID extracts user ID from request headers or context
func extractUserID(request events.APIGatewayProxyRequest) string {
	// Try to get user ID from Authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"]
	}

	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		// In a real implementation, you would validate the JWT token
		// and extract the user ID from it
		// For now, we'll return a placeholder
		return "authenticated-user"
	}

	// Try to get user ID from metadata in request body (for anonymous feedback)
	if request.Body != "" {
		var bodyMap map[string]interface{}
		if err := json.Unmarshal([]byte(request.Body), &bodyMap); err == nil {
			if metadata, exists := bodyMap["metadata"].(map[string]interface{}); exists {
				if userID, exists := metadata["userId"].(string); exists && userID != "" {
					return userID
				}
			}
		}
	}

	// Return empty string for anonymous users
	return ""
}

// isValidCategory checks if the feedback category is valid
func isValidCategory(category models.FeedbackCategory) bool {
	validCategories := []models.FeedbackCategory{
		models.BugReport,
		models.FeatureRequest,
		models.GeneralFeedback,
		models.UserExperience,
		models.Performance,
		models.Other,
	}

	for _, valid := range validCategories {
		if category == valid {
			return true
		}
	}
	return false
}

// createErrorResponse creates a standardized error response
func createErrorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	errorResponse := map[string]interface{}{
		"success": false,
		"error":   message,
	}

	responseBody, _ := json.Marshal(errorResponse)

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    getCORSHeaders(),
		Body:       string(responseBody),
	}
}

// getCORSHeaders returns CORS headers for API responses
func getCORSHeaders() map[string]string {
	return map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, OPTIONS",
		"Access-Control-Allow-Headers":     "Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token",
		"Access-Control-Allow-Credentials": "false",
		"Content-Type":                     "application/json",
	}
}