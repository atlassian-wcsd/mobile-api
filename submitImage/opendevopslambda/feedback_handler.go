package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/google/uuid"
)

// FeedbackHandler handles feedback-related operations
type FeedbackHandler struct {
	dynamoDB dynamodbiface.DynamoDBAPI
	s3       s3iface.S3API
}

// NewFeedbackHandler creates a new feedback handler
func NewFeedbackHandler(dynamoDB dynamodbiface.DynamoDBAPI, s3 s3iface.S3API) *FeedbackHandler {
	return &FeedbackHandler{
		dynamoDB: dynamoDB,
		s3:       s3,
	}
}

// Feedback represents a user feedback entry
type Feedback struct {
	ID          string            `json:"id"`
	UserID      string            `json:"userId,omitempty"`
	Email       string            `json:"email,omitempty"`
	Type        string            `json:"type"`
	Category    string            `json:"category"`
	Subject     string            `json:"subject"`
	Message     string            `json:"message"`
	Rating      int               `json:"rating,omitempty"`
	DeviceInfo  map[string]string `json:"deviceInfo"`
	AppVersion  string            `json:"appVersion"`
	CreatedAt   string            `json:"createdAt"`
	Status      string            `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// FeedbackRequest represents the request payload for submitting feedback
type FeedbackRequest struct {
	Type     string                 `json:"type"`
	Category string                 `json:"category"`
	Subject  string                 `json:"subject"`
	Message  string                 `json:"message"`
	Rating   int                    `json:"rating,omitempty"`
	Email    string                 `json:"email,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FeedbackResponse represents the response for feedback operations
type FeedbackResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// HandleSubmitFeedback handles feedback submission
func (fh *FeedbackHandler) HandleSubmitFeedback(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback submission")

	// Parse request body
	var feedbackReq FeedbackRequest
	if err := json.Unmarshal([]byte(request.Body), &feedbackReq); err != nil {
		log.Printf("Error parsing request body: %v", err)
		return createErrorResponse(400, "Invalid request body"), nil
	}

	// Validate required fields
	if err := validateFeedbackRequest(feedbackReq); err != nil {
		log.Printf("Validation error: %v", err)
		return createErrorResponse(400, err.Error()), nil
	}

	// Extract user ID from auth token if present
	userID := ""
	if authHeader := request.Headers["Authorization"]; authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// In a real implementation, you would validate the JWT token here
			// For now, we'll extract a mock user ID
			userID = extractUserIDFromToken(token)
		}
	}

	// Create feedback entry
	feedback := Feedback{
		ID:         uuid.New().String(),
		UserID:     userID,
		Email:      feedbackReq.Email,
		Type:       feedbackReq.Type,
		Category:   feedbackReq.Category,
		Subject:    feedbackReq.Subject,
		Message:    feedbackReq.Message,
		Rating:     feedbackReq.Rating,
		DeviceInfo: extractDeviceInfo(request),
		AppVersion: "1.0.0", // This could be extracted from headers
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Status:     "submitted",
		Metadata:   feedbackReq.Metadata,
	}

	// Store feedback in DynamoDB
	if err := fh.storeFeedback(feedback); err != nil {
		log.Printf("Error storing feedback: %v", err)
		return createErrorResponse(500, "Failed to store feedback"), nil
	}

	// Send notification (in a real implementation, you might send an email or SNS notification)
	go fh.sendFeedbackNotification(feedback)

	response := FeedbackResponse{
		Success:    true,
		FeedbackID: feedback.ID,
		Message:    "Feedback submitted successfully",
	}

	responseBody, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(responseBody),
	}, nil
}

// HandleGetFeedbackHistory retrieves feedback history for a user
func (fh *FeedbackHandler) HandleGetFeedbackHistory(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback history request")

	// Extract user ID from auth token
	userID := ""
	if authHeader := request.Headers["Authorization"]; authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			userID = extractUserIDFromToken(token)
		}
	}

	if userID == "" {
		return createErrorResponse(401, "Authentication required"), nil
	}

	// Get limit from query parameters
	limit := 10
	if limitParam := request.QueryStringParameters["limit"]; limitParam != "" {
		// Parse limit (simplified for this example)
		if limitParam == "20" {
			limit = 20
		} else if limitParam == "50" {
			limit = 50
		}
	}

	feedbacks, err := fh.getFeedbackHistory(userID, limit)
	if err != nil {
		log.Printf("Error retrieving feedback history: %v", err)
		return createErrorResponse(500, "Failed to retrieve feedback history"), nil
	}

	response := map[string]interface{}{
		"feedbacks": feedbacks,
	}

	responseBody, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(responseBody),
	}, nil
}

// HandleGetFeedbackStatus retrieves feedback status by ID
func (fh *FeedbackHandler) HandleGetFeedbackStatus(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling feedback status request")

	feedbackID := request.PathParameters["id"]
	if feedbackID == "" {
		return createErrorResponse(400, "Feedback ID is required"), nil
	}

	feedback, err := fh.getFeedbackByID(feedbackID)
	if err != nil {
		log.Printf("Error retrieving feedback: %v", err)
		return createErrorResponse(500, "Failed to retrieve feedback"), nil
	}

	if feedback == nil {
		return createErrorResponse(404, "Feedback not found"), nil
	}

	response := map[string]interface{}{
		"feedback": feedback,
	}

	responseBody, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
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
func (fh *FeedbackHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
	}, nil
}

// storeFeedback stores feedback in DynamoDB
func (fh *FeedbackHandler) storeFeedback(feedback Feedback) error {
	// Convert metadata to DynamoDB format
	metadataAttr := make(map[string]*dynamodb.AttributeValue)
	if feedback.Metadata != nil {
		for key, value := range feedback.Metadata {
			if strValue, ok := value.(string); ok {
				metadataAttr[key] = &dynamodb.AttributeValue{S: aws.String(strValue)}
			}
		}
	}

	// Convert device info to DynamoDB format
	deviceInfoAttr := make(map[string]*dynamodb.AttributeValue)
	for key, value := range feedback.DeviceInfo {
		deviceInfoAttr[key] = &dynamodb.AttributeValue{S: aws.String(value)}
	}

	item := map[string]*dynamodb.AttributeValue{
		"Id":         {S: aws.String(feedback.ID)},
		"Type":       {S: aws.String(feedback.Type)},
		"Category":   {S: aws.String(feedback.Category)},
		"Subject":    {S: aws.String(feedback.Subject)},
		"Message":    {S: aws.String(feedback.Message)},
		"AppVersion": {S: aws.String(feedback.AppVersion)},
		"CreatedAt":  {S: aws.String(feedback.CreatedAt)},
		"Status":     {S: aws.String(feedback.Status)},
		"DeviceInfo": {M: deviceInfoAttr},
	}

	// Add optional fields
	if feedback.UserID != "" {
		item["UserId"] = &dynamodb.AttributeValue{S: aws.String(feedback.UserID)}
	}
	if feedback.Email != "" {
		item["Email"] = &dynamodb.AttributeValue{S: aws.String(feedback.Email)}
	}
	if feedback.Rating > 0 {
		item["Rating"] = &dynamodb.AttributeValue{N: aws.String(fmt.Sprintf("%d", feedback.Rating))}
	}
	if len(metadataAttr) > 0 {
		item["Metadata"] = &dynamodb.AttributeValue{M: metadataAttr}
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String("UserFeedback"),
		Item:      item,
	}

	_, err := fh.dynamoDB.PutItem(input)
	return err
}

// getFeedbackHistory retrieves feedback history for a user
func (fh *FeedbackHandler) getFeedbackHistory(userID string, limit int) ([]Feedback, error) {
	// This is a simplified implementation
	// In a real application, you would use a GSI on UserId for efficient querying
	input := &dynamodb.ScanInput{
		TableName:        aws.String("UserFeedback"),
		FilterExpression: aws.String("UserId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {S: aws.String(userID)},
		},
		Limit: aws.Int64(int64(limit)),
	}

	result, err := fh.dynamoDB.Scan(input)
	if err != nil {
		return nil, err
	}

	var feedbacks []Feedback
	for _, item := range result.Items {
		feedback := Feedback{
			ID:         aws.StringValue(item["Id"].S),
			Type:       aws.StringValue(item["Type"].S),
			Category:   aws.StringValue(item["Category"].S),
			Subject:    aws.StringValue(item["Subject"].S),
			Message:    aws.StringValue(item["Message"].S),
			AppVersion: aws.StringValue(item["AppVersion"].S),
			CreatedAt:  aws.StringValue(item["CreatedAt"].S),
			Status:     aws.StringValue(item["Status"].S),
		}

		if item["UserId"] != nil {
			feedback.UserID = aws.StringValue(item["UserId"].S)
		}
		if item["Email"] != nil {
			feedback.Email = aws.StringValue(item["Email"].S)
		}
		if item["Rating"] != nil {
			// Parse rating from string to int
			feedback.Rating = 0 // Simplified for this example
		}

		feedbacks = append(feedbacks, feedback)
	}

	return feedbacks, nil
}

// getFeedbackByID retrieves feedback by ID
func (fh *FeedbackHandler) getFeedbackByID(feedbackID string) (*Feedback, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("UserFeedback"),
		Key: map[string]*dynamodb.AttributeValue{
			"Id": {S: aws.String(feedbackID)},
		},
	}

	result, err := fh.dynamoDB.GetItem(input)
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, nil
	}

	feedback := &Feedback{
		ID:         aws.StringValue(result.Item["Id"].S),
		Type:       aws.StringValue(result.Item["Type"].S),
		Category:   aws.StringValue(result.Item["Category"].S),
		Subject:    aws.StringValue(result.Item["Subject"].S),
		Message:    aws.StringValue(result.Item["Message"].S),
		AppVersion: aws.StringValue(result.Item["AppVersion"].S),
		CreatedAt:  aws.StringValue(result.Item["CreatedAt"].S),
		Status:     aws.StringValue(result.Item["Status"].S),
	}

	if result.Item["UserId"] != nil {
		feedback.UserID = aws.StringValue(result.Item["UserId"].S)
	}
	if result.Item["Email"] != nil {
		feedback.Email = aws.StringValue(result.Item["Email"].S)
	}

	return feedback, nil
}

// sendFeedbackNotification sends a notification about new feedback
func (fh *FeedbackHandler) sendFeedbackNotification(feedback Feedback) {
	// In a real implementation, you would send an email or SNS notification
	log.Printf("New feedback received: ID=%s, Type=%s, Subject=%s", feedback.ID, feedback.Type, feedback.Subject)
}

// Helper functions

func validateFeedbackRequest(req FeedbackRequest) error {
	if req.Type == "" {
		return fmt.Errorf("feedback type is required")
	}
	if req.Category == "" {
		return fmt.Errorf("feedback category is required")
	}
	if len(req.Subject) < 5 || len(req.Subject) > 100 {
		return fmt.Errorf("subject must be between 5 and 100 characters")
	}
	if len(req.Message) < 10 || len(req.Message) > 2000 {
		return fmt.Errorf("message must be between 10 and 2000 characters")
	}
	if req.Rating < 0 || req.Rating > 5 {
		return fmt.Errorf("rating must be between 1 and 5")
	}
	return nil
}

func extractUserIDFromToken(token string) string {
	// In a real implementation, you would validate and parse the JWT token
	// For this example, we'll return a mock user ID
	return "user_" + token[:8] // Use first 8 characters as mock user ID
}

func extractDeviceInfo(request events.APIGatewayProxyRequest) map[string]string {
	deviceInfo := make(map[string]string)
	
	if userAgent := request.Headers["User-Agent"]; userAgent != "" {
		deviceInfo["userAgent"] = userAgent
	}
	if xForwardedFor := request.Headers["X-Forwarded-For"]; xForwardedFor != "" {
		deviceInfo["ipAddress"] = strings.Split(xForwardedFor, ",")[0]
	}
	if acceptLanguage := request.Headers["Accept-Language"]; acceptLanguage != "" {
		deviceInfo["language"] = acceptLanguage
	}
	
	return deviceInfo
}

func createErrorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	errorResponse := FeedbackResponse{
		Success: false,
		Message: message,
		Error:   message,
	}
	
	responseBody, _ := json.Marshal(errorResponse)
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