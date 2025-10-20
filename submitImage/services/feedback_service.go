package services

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"submit-image/models"
)

// FeedbackService handles feedback operations
type FeedbackService struct {
	dynamoDB  dynamodbiface.DynamoDBAPI
	tableName string
}

// NewFeedbackService creates a new feedback service
func NewFeedbackService(dynamoDB dynamodbiface.DynamoDBAPI) *FeedbackService {
	return &FeedbackService{
		dynamoDB:  dynamoDB,
		tableName: "UserFeedback", // DynamoDB table name
	}
}

// SubmitFeedback stores feedback in DynamoDB
func (s *FeedbackService) SubmitFeedback(req *models.FeedbackSubmissionRequest, userAgent string) (*models.FeedbackSubmissionResponse, error) {
	// Validate the request
	if err := req.Validate(); err != nil {
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Generate unique ID
	feedbackID := uuid.New().String()

	// Create feedback object
	feedback := &models.Feedback{
		ID:        feedbackID,
		Email:     req.Email,
		Name:      req.Name,
		Type:      req.Type,
		Rating:    req.Rating,
		Subject:   req.Subject,
		Message:   req.Message,
		Page:      req.Page,
		UserAgent: userAgent,
		CreatedAt: time.Now().UTC(),
		Status:    models.FeedbackStatusNew,
		Metadata:  req.Metadata,
	}

	// Convert to DynamoDB item
	item, err := dynamodbattribute.MarshalMap(feedback)
	if err != nil {
		log.Printf("Error marshaling feedback: %v", err)
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Error:   "Failed to process feedback",
		}, err
	}

	// Store in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	}

	_, err = s.dynamoDB.PutItem(input)
	if err != nil {
		log.Printf("Error storing feedback in DynamoDB: %v", err)
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Error:   "Failed to store feedback",
		}, err
	}

	log.Printf("Feedback submitted successfully: %s", feedbackID)

	return &models.FeedbackSubmissionResponse{
		Success:    true,
		FeedbackID: feedbackID,
		Message:    "Feedback submitted successfully",
	}, nil
}

// GetFeedback retrieves feedback by ID
func (s *FeedbackService) GetFeedback(feedbackID string) (*models.Feedback, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
	}

	result, err := s.dynamoDB.GetItem(input)
	if err != nil {
		log.Printf("Error getting feedback from DynamoDB: %v", err)
		return nil, err
	}

	if result.Item == nil {
		return nil, nil // Not found
	}

	var feedback models.Feedback
	err = dynamodbattribute.UnmarshalMap(result.Item, &feedback)
	if err != nil {
		log.Printf("Error unmarshaling feedback: %v", err)
		return nil, err
	}

	return &feedback, nil
}

// GetUserFeedback retrieves all feedback for a specific user
func (s *FeedbackService) GetUserFeedback(userID string) ([]models.Feedback, error) {
	// Create a GSI query for userId (assuming we have a GSI on userId)
	input := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("UserIdIndex"), // GSI name
		KeyConditionExpression: aws.String("userId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {
				S: aws.String(userID),
			},
		},
		ScanIndexForward: aws.Bool(false), // Sort by creation date descending
	}

	result, err := s.dynamoDB.Query(input)
	if err != nil {
		log.Printf("Error querying user feedback from DynamoDB: %v", err)
		return nil, err
	}

	var feedbackList []models.Feedback
	for _, item := range result.Items {
		var feedback models.Feedback
		err = dynamodbattribute.UnmarshalMap(item, &feedback)
		if err != nil {
			log.Printf("Error unmarshaling feedback item: %v", err)
			continue
		}
		feedbackList = append(feedbackList, feedback)
	}

	return feedbackList, nil
}

// GetAllFeedback retrieves all feedback (for admin use)
func (s *FeedbackService) GetAllFeedback(limit int) ([]models.Feedback, error) {
	input := &dynamodb.ScanInput{
		TableName: aws.String(s.tableName),
	}

	if limit > 0 {
		input.Limit = aws.Int64(int64(limit))
	}

	result, err := s.dynamoDB.Scan(input)
	if err != nil {
		log.Printf("Error scanning feedback from DynamoDB: %v", err)
		return nil, err
	}

	var feedbackList []models.Feedback
	for _, item := range result.Items {
		var feedback models.Feedback
		err = dynamodbattribute.UnmarshalMap(item, &feedback)
		if err != nil {
			log.Printf("Error unmarshaling feedback item: %v", err)
			continue
		}
		feedbackList = append(feedbackList, feedback)
	}

	return feedbackList, nil
}

// UpdateFeedbackStatus updates the status of feedback
func (s *FeedbackService) UpdateFeedbackStatus(feedbackID string, status models.FeedbackStatus) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
		UpdateExpression: aws.String("SET #status = :status"),
		ExpressionAttributeNames: map[string]*string{
			"#status": aws.String("status"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":status": {
				S: aws.String(string(status)),
			},
		},
	}

	_, err := s.dynamoDB.UpdateItem(input)
	if err != nil {
		log.Printf("Error updating feedback status in DynamoDB: %v", err)
		return err
	}

	log.Printf("Feedback status updated successfully: %s -> %s", feedbackID, status)
	return nil
}

// DeleteFeedback deletes feedback by ID
func (s *FeedbackService) DeleteFeedback(feedbackID string) error {
	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
	}

	_, err := s.dynamoDB.DeleteItem(input)
	if err != nil {
		log.Printf("Error deleting feedback from DynamoDB: %v", err)
		return err
	}

	log.Printf("Feedback deleted successfully: %s", feedbackID)
	return nil
}

// GetFeedbackStats returns basic statistics about feedback
func (s *FeedbackService) GetFeedbackStats() (map[string]interface{}, error) {
	// This is a simplified version - in production you might want to use DynamoDB aggregation
	// or maintain separate counters
	
	input := &dynamodb.ScanInput{
		TableName: aws.String(s.tableName),
		Select:    aws.String("COUNT"),
	}

	result, err := s.dynamoDB.Scan(input)
	if err != nil {
		log.Printf("Error getting feedback stats from DynamoDB: %v", err)
		return nil, err
	}

	stats := map[string]interface{}{
		"totalFeedback": *result.Count,
		"scannedCount":  *result.ScannedCount,
	}

	return stats, nil
}