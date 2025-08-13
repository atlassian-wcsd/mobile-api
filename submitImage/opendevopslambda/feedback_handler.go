package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"submit-image/models"
)

// FeedbackHandler handles feedback-related operations
type FeedbackHandler struct {
	dynamoDB dynamodbiface.DynamoDBAPI
}

// NewFeedbackHandler creates a new feedback handler
func NewFeedbackHandler(dynamoDB dynamodbiface.DynamoDBAPI) *FeedbackHandler {
	return &FeedbackHandler{
		dynamoDB: dynamoDB,
	}
}

// HandleSubmitFeedback handles feedback submission
func (h *FeedbackHandler) HandleSubmitFeedback(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback submission")

	// Parse request body
	var feedbackRequest models.FeedbackSubmissionRequest
	if err := json.Unmarshal([]byte(request.Body), &feedbackRequest); err != nil {
		log.Printf("Error parsing request body: %v", err)
		return h.createErrorResponse(http.StatusBadRequest, "Invalid request body"), nil
	}

	// Validate request
	if err := h.validateFeedbackRequest(&feedbackRequest); err != nil {
		log.Printf("Validation error: %v", err)
		return h.createErrorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// Extract user ID from authorization header if present
	userID := h.extractUserIDFromAuth(request.Headers)

	// Create feedback object
	feedback := &models.Feedback{
		ID:          uuid.New().String(),
		UserID:      userID,
		Email:       feedbackRequest.Email,
		Rating:      feedbackRequest.Rating,
		Category:    feedbackRequest.Category,
		Subject:     strings.TrimSpace(feedbackRequest.Subject),
		Message:     strings.TrimSpace(feedbackRequest.Message),
		Attachments: []string{}, // TODO: Implement file upload handling
		DeviceInfo:  feedbackRequest.DeviceInfo,
		CreatedAt:   time.Now().UTC(),
		Status:      models.StatusSubmitted,
		Metadata: map[string]string{
			"source":    "web_app",
			"ip":        h.getClientIP(request),
			"userAgent": h.getUserAgent(request),
		},
	}

	// Save to DynamoDB
	if err := h.saveFeedback(feedback); err != nil {
		log.Printf("Error saving feedback: %v", err)
		return h.createErrorResponse(http.StatusInternalServerError, "Failed to save feedback"), nil
	}

	// Create response
	response := models.FeedbackSubmissionResponse{
		Success:    true,
		FeedbackID: feedback.ID,
		Message:    "Feedback submitted successfully",
	}

	responseBody, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusCreated,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(responseBody),
	}, nil
}

// HandleGetFeedbackHistory handles getting feedback history for a user
func (h *FeedbackHandler) HandleGetFeedbackHistory(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback history request")

	// Extract user ID from authorization header
	userID := h.extractUserIDFromAuth(request.Headers)
	if userID == "" {
		return h.createErrorResponse(http.StatusUnauthorized, "Authentication required"), nil
	}

	// Get feedback from DynamoDB
	feedback, err := h.getFeedbackByUserID(userID)
	if err != nil {
		log.Printf("Error getting feedback history: %v", err)
		return h.createErrorResponse(http.StatusInternalServerError, "Failed to get feedback history"), nil
	}

	// Create response
	response := models.FeedbackListResponse{
		Success:  true,
		Feedback: feedback,
		Count:    len(feedback),
	}

	responseBody, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(responseBody),
	}, nil
}

// HandleOptions handles CORS preflight requests
func (h *FeedbackHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
	}, nil
}

// validateFeedbackRequest validates the feedback submission request
func (h *FeedbackHandler) validateFeedbackRequest(req *models.FeedbackSubmissionRequest) error {
	if req.Rating < 1 || req.Rating > 5 {
		return fmt.Errorf("rating must be between 1 and 5")
	}

	if !models.IsValidCategory(req.Category) {
		return fmt.Errorf("invalid category: %s", req.Category)
	}

	subject := strings.TrimSpace(req.Subject)
	if len(subject) < 3 || len(subject) > 100 {
		return fmt.Errorf("subject must be between 3 and 100 characters")
	}

	message := strings.TrimSpace(req.Message)
	if len(message) < 10 || len(message) > 2000 {
		return fmt.Errorf("message must be between 10 and 2000 characters")
	}

	if req.Email != "" && !h.isValidEmail(req.Email) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// saveFeedback saves feedback to DynamoDB
func (h *FeedbackHandler) saveFeedback(feedback *models.Feedback) error {
	// Convert feedback to DynamoDB item
	item := map[string]*dynamodb.AttributeValue{
		"id": {
			S: aws.String(feedback.ID),
		},
		"rating": {
			N: aws.String(fmt.Sprintf("%d", feedback.Rating)),
		},
		"category": {
			S: aws.String(feedback.Category),
		},
		"subject": {
			S: aws.String(feedback.Subject),
		},
		"message": {
			S: aws.String(feedback.Message),
		},
		"createdAt": {
			S: aws.String(feedback.CreatedAt.Format(time.RFC3339)),
		},
		"status": {
			S: aws.String(feedback.Status),
		},
	}

	// Add optional fields
	if feedback.UserID != "" {
		item["userId"] = &dynamodb.AttributeValue{S: aws.String(feedback.UserID)}
	}
	if feedback.Email != "" {
		item["email"] = &dynamodb.AttributeValue{S: aws.String(feedback.Email)}
	}

	// Add device info if present
	if feedback.DeviceInfo != nil {
		deviceInfoMap := map[string]*dynamodb.AttributeValue{
			"userAgent": {S: aws.String(feedback.DeviceInfo.UserAgent)},
			"platform":  {S: aws.String(feedback.DeviceInfo.Platform)},
		}
		if feedback.DeviceInfo.ScreenResolution != "" {
			deviceInfoMap["screenResolution"] = &dynamodb.AttributeValue{S: aws.String(feedback.DeviceInfo.ScreenResolution)}
		}
		if feedback.DeviceInfo.Viewport != "" {
			deviceInfoMap["viewport"] = &dynamodb.AttributeValue{S: aws.String(feedback.DeviceInfo.Viewport)}
		}
		item["deviceInfo"] = &dynamodb.AttributeValue{M: deviceInfoMap}
	}

	// Add metadata
	if len(feedback.Metadata) > 0 {
		metadataMap := make(map[string]*dynamodb.AttributeValue)
		for key, value := range feedback.Metadata {
			metadataMap[key] = &dynamodb.AttributeValue{S: aws.String(value)}
		}
		item["metadata"] = &dynamodb.AttributeValue{M: metadataMap}
	}

	// Put item in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String("Feedback"),
		Item:      item,
	}

	_, err := h.dynamoDB.PutItem(input)
	return err
}

// getFeedbackByUserID gets feedback for a specific user
func (h *FeedbackHandler) getFeedbackByUserID(userID string) ([]models.Feedback, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String("Feedback"),
		IndexName:              aws.String("UserIdIndex"),
		KeyConditionExpression: aws.String("userId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {S: aws.String(userID)},
		},
		ScanIndexForward: aws.Bool(false), // Sort by creation date descending
	}

	result, err := h.dynamoDB.Query(input)
	if err != nil {
		return nil, err
	}

	var feedback []models.Feedback
	for _, item := range result.Items {
		fb, err := h.dynamoItemToFeedback(item)
		if err != nil {
			log.Printf("Error converting DynamoDB item to feedback: %v", err)
			continue
		}
		feedback = append(feedback, *fb)
	}

	return feedback, nil
}

// dynamoItemToFeedback converts a DynamoDB item to a Feedback struct
func (h *FeedbackHandler) dynamoItemToFeedback(item map[string]*dynamodb.AttributeValue) (*models.Feedback, error) {
	feedback := &models.Feedback{}

	if item["id"] != nil && item["id"].S != nil {
		feedback.ID = *item["id"].S
	}
	if item["userId"] != nil && item["userId"].S != nil {
		feedback.UserID = *item["userId"].S
	}
	if item["email"] != nil && item["email"].S != nil {
		feedback.Email = *item["email"].S
	}
	if item["rating"] != nil && item["rating"].N != nil {
		rating := 0
		fmt.Sscanf(*item["rating"].N, "%d", &rating)
		feedback.Rating = rating
	}
	if item["category"] != nil && item["category"].S != nil {
		feedback.Category = *item["category"].S
	}
	if item["subject"] != nil && item["subject"].S != nil {
		feedback.Subject = *item["subject"].S
	}
	if item["message"] != nil && item["message"].S != nil {
		feedback.Message = *item["message"].S
	}
	if item["status"] != nil && item["status"].S != nil {
		feedback.Status = *item["status"].S
	}
	if item["createdAt"] != nil && item["createdAt"].S != nil {
		if createdAt, err := time.Parse(time.RFC3339, *item["createdAt"].S); err == nil {
			feedback.CreatedAt = createdAt
		}
	}

	return feedback, nil
}

// Helper functions
func (h *FeedbackHandler) extractUserIDFromAuth(headers map[string]string) string {
	authHeader := headers["Authorization"]
	if authHeader == "" {
		authHeader = headers["authorization"]
	}
	
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		// TODO: Implement JWT token validation and extract user ID
		// For now, return empty string
		return ""
	}
	
	return ""
}

func (h *FeedbackHandler) getClientIP(request events.APIGatewayProxyRequest) string {
	if ip := request.Headers["X-Forwarded-For"]; ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := request.Headers["X-Real-IP"]; ip != "" {
		return ip
	}
	return request.RequestContext.Identity.SourceIP
}

func (h *FeedbackHandler) getUserAgent(request events.APIGatewayProxyRequest) string {
	return request.Headers["User-Agent"]
}

func (h *FeedbackHandler) isValidEmail(email string) bool {
	// Simple email validation
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (h *FeedbackHandler) createErrorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	response := models.FeedbackSubmissionResponse{
		Success: false,
		Error:   message,
	}
	responseBody, _ := json.Marshal(response)
	
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(responseBody),
	}
}