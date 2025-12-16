package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"submit-image/models"
)

const (
	FeedbackTableName = "UserFeedback"
	MetricsTableName  = "UserMetrics"
)

// FeedbackHandler handles feedback and metrics operations
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
	// Extract user ID from authorization token
	userID, err := h.extractUserID(request)
	if err != nil {
		return h.errorResponse(401, "Unauthorized: "+err.Error()), nil
	}

	// Parse request body
	var feedbackReq models.FeedbackSubmitRequest
	if err := json.Unmarshal([]byte(request.Body), &feedbackReq); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Validate feedback request
	if err := h.validateFeedbackRequest(&feedbackReq); err != nil {
		return h.errorResponse(400, "Validation error: "+err.Error()), nil
	}

	// Create feedback object
	feedback := &models.Feedback{
		ID:            uuid.New().String(),
		UserID:        userID,
		FeedbackType:  feedbackReq.FeedbackType,
		Rating:        feedbackReq.Rating,
		Title:         feedbackReq.Title,
		Message:       feedbackReq.Message,
		Category:      feedbackReq.Category,
		PageContext:   feedbackReq.PageContext,
		UserAgent:     request.RequestContext.Identity.UserAgent,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Email:         feedbackReq.Email,
		AllowContact:  feedbackReq.AllowContact,
		AttachmentIDs: feedbackReq.AttachmentIDs,
	}

	// Extract device info from user agent
	feedback.DeviceInfo = h.extractDeviceInfo(request.RequestContext.Identity.UserAgent)

	// Save to DynamoDB
	if err := h.saveFeedback(feedback); err != nil {
		return h.errorResponse(500, "Failed to save feedback: "+err.Error()), nil
	}

	// Return success response
	response := &models.FeedbackSubmitResponse{
		Success:    true,
		FeedbackID: feedback.ID,
		Message:    "Feedback submitted successfully. Thank you for your input!",
	}

	return h.jsonResponse(200, response), nil
}

// HandleTrackMetric handles metric/event tracking
func (h *FeedbackHandler) HandleTrackMetric(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract user ID from authorization token
	userID, err := h.extractUserID(request)
	if err != nil {
		return h.errorResponse(401, "Unauthorized: "+err.Error()), nil
	}

	// Parse request body
	var metricReq models.MetricTrackRequest
	if err := json.Unmarshal([]byte(request.Body), &metricReq); err != nil {
		return h.errorResponse(400, "Invalid request body"), nil
	}

	// Validate metric request
	if metricReq.EventType == "" || metricReq.EventName == "" {
		return h.errorResponse(400, "EventType and EventName are required"), nil
	}

	// Create metric object
	metric := &models.UserMetric{
		ID:         uuid.New().String(),
		UserID:     userID,
		EventType:  metricReq.EventType,
		EventName:  metricReq.EventName,
		Properties: metricReq.Properties,
		SessionID:  metricReq.SessionID,
		Page:       metricReq.Page,
		Duration:   metricReq.Duration,
		Timestamp:  time.Now(),
	}

	// Extract context information
	metric.Context = h.extractMetricContext(request)

	// Save to DynamoDB
	if err := h.saveMetric(metric); err != nil {
		return h.errorResponse(500, "Failed to save metric: "+err.Error()), nil
	}

	// Return success response
	response := &models.MetricTrackResponse{
		Success:  true,
		MetricID: metric.ID,
		Message:  "Metric tracked successfully",
	}

	return h.jsonResponse(200, response), nil
}

// HandleGetFeedback retrieves feedback for a user
func (h *FeedbackHandler) HandleGetFeedback(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Extract user ID from authorization token
	userID, err := h.extractUserID(request)
	if err != nil {
		return h.errorResponse(401, "Unauthorized: "+err.Error()), nil
	}

	// Query feedback by user ID
	input := &dynamodb.QueryInput{
		TableName:              aws.String(FeedbackTableName),
		IndexName:              aws.String("UserIdIndex"),
		KeyConditionExpression: aws.String("UserId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {S: aws.String(userID)},
		},
		ScanIndexForward: aws.Bool(false), // Most recent first
		Limit:            aws.Int64(50),   // Limit results
	}

	result, err := h.dynamoDB.Query(input)
	if err != nil {
		return h.errorResponse(500, "Failed to retrieve feedback: "+err.Error()), nil
	}

	// Unmarshal results
	var feedbackList []models.Feedback
	if err := dynamodbattribute.UnmarshalListOfMaps(result.Items, &feedbackList); err != nil {
		return h.errorResponse(500, "Failed to parse feedback: "+err.Error()), nil
	}

	return h.jsonResponse(200, map[string]interface{}{
		"success":  true,
		"feedback": feedbackList,
		"count":    len(feedbackList),
	}), nil
}

// Helper methods

func (h *FeedbackHandler) saveFeedback(feedback *models.Feedback) error {
	item, err := dynamodbattribute.MarshalMap(feedback)
	if err != nil {
		return fmt.Errorf("failed to marshal feedback: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(FeedbackTableName),
		Item:      item,
	}

	_, err = h.dynamoDB.PutItem(input)
	return err
}

func (h *FeedbackHandler) saveMetric(metric *models.UserMetric) error {
	item, err := dynamodbattribute.MarshalMap(metric)
	if err != nil {
		return fmt.Errorf("failed to marshal metric: %w", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(MetricsTableName),
		Item:      item,
	}

	_, err = h.dynamoDB.PutItem(input)
	return err
}

func (h *FeedbackHandler) extractUserID(request events.APIGatewayProxyRequest) (string, error) {
	// Extract from Authorization header
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		authHeader = request.Headers["authorization"]
	}

	if authHeader == "" {
		return "", fmt.Errorf("authorization header required")
	}

	// Extract token from "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	token := parts[1]

	// Initialize JWT manager (in production, this should be initialized once)
	// For now, we'll use a simple token validation
	// In a real implementation, you should:
	// 1. Get JWT secret from environment variable or AWS Secrets Manager
	// 2. Verify the token signature
	// 3. Check token expiration
	// 4. Extract user ID from claims
	
	// Temporary: For development/testing, extract user ID from token
	// In production, replace this with proper JWT verification
	if token != "" {
		// TODO: Replace with actual JWT verification
		// jwtManager := NewJWTManager(os.Getenv("JWT_SECRET"), "signature-app")
		// claims, err := jwtManager.VerifyToken(token)
		// if err != nil {
		//     return "", fmt.Errorf("invalid token: %w", err)
		// }
		// return claims.UserID, nil
		
		// Placeholder for development
		return "user_" + token[:min(10, len(token))], nil
	}

	return "", fmt.Errorf("invalid token")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *FeedbackHandler) extractDeviceInfo(userAgent string) *models.DeviceInfo {
	// Basic user agent parsing
	// In production, use a proper user agent parser library
	deviceInfo := &models.DeviceInfo{
		Platform: "unknown",
		Browser:  "unknown",
		IsMobile: false,
	}

	userAgentLower := strings.ToLower(userAgent)

	// Detect mobile
	if strings.Contains(userAgentLower, "mobile") || 
	   strings.Contains(userAgentLower, "android") ||
	   strings.Contains(userAgentLower, "iphone") {
		deviceInfo.IsMobile = true
	}

	// Detect platform
	if strings.Contains(userAgentLower, "windows") {
		deviceInfo.Platform = "Windows"
	} else if strings.Contains(userAgentLower, "mac") {
		deviceInfo.Platform = "macOS"
	} else if strings.Contains(userAgentLower, "linux") {
		deviceInfo.Platform = "Linux"
	} else if strings.Contains(userAgentLower, "android") {
		deviceInfo.Platform = "Android"
	} else if strings.Contains(userAgentLower, "iphone") || strings.Contains(userAgentLower, "ipad") {
		deviceInfo.Platform = "iOS"
	}

	// Detect browser
	if strings.Contains(userAgentLower, "chrome") {
		deviceInfo.Browser = "Chrome"
	} else if strings.Contains(userAgentLower, "safari") {
		deviceInfo.Browser = "Safari"
	} else if strings.Contains(userAgentLower, "firefox") {
		deviceInfo.Browser = "Firefox"
	} else if strings.Contains(userAgentLower, "edge") {
		deviceInfo.Browser = "Edge"
	}

	return deviceInfo
}

func (h *FeedbackHandler) extractMetricContext(request events.APIGatewayProxyRequest) *models.MetricContext {
	userAgent := request.RequestContext.Identity.UserAgent
	deviceInfo := h.extractDeviceInfo(userAgent)

	return &models.MetricContext{
		UserAgent: userAgent,
		Platform:  deviceInfo.Platform,
		Browser:   deviceInfo.Browser,
		IsMobile:  deviceInfo.IsMobile,
		IsTablet:  false, // TODO: Implement tablet detection
	}
}

func (h *FeedbackHandler) validateFeedbackRequest(req *models.FeedbackSubmitRequest) error {
	if req.FeedbackType == "" {
		return fmt.Errorf("feedbackType is required")
	}

	validTypes := map[string]bool{"bug": true, "feature": true, "improvement": true, "general": true}
	if !validTypes[req.FeedbackType] {
		return fmt.Errorf("invalid feedbackType")
	}

	if len(req.Title) < 3 || len(req.Title) > 200 {
		return fmt.Errorf("title must be between 3 and 200 characters")
	}

	if len(req.Message) < 10 || len(req.Message) > 5000 {
		return fmt.Errorf("message must be between 10 and 5000 characters")
	}

	if req.Category == "" {
		return fmt.Errorf("category is required")
	}

	if req.Rating != nil && (*req.Rating < 1 || *req.Rating > 5) {
		return fmt.Errorf("rating must be between 1 and 5")
	}

	return nil
}

func (h *FeedbackHandler) jsonResponse(statusCode int, data interface{}) events.APIGatewayProxyResponse {
	body, _ := json.Marshal(data)

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:            string(body),
		IsBase64Encoded: false,
	}
}

func (h *FeedbackHandler) errorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	return h.jsonResponse(statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
