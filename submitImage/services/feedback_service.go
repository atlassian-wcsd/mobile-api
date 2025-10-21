package services

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"

	"submit-image/models"
)

// FeedbackService handles feedback operations
type FeedbackService struct {
	dynamoDB dynamodbiface.DynamoDBAPI
}

// NewFeedbackService creates a new feedback service
func NewFeedbackService(dynamoDB dynamodbiface.DynamoDBAPI) *FeedbackService {
	return &FeedbackService{
		dynamoDB: dynamoDB,
	}
}

// SubmitFeedback stores new feedback in DynamoDB
func (fs *FeedbackService) SubmitFeedback(req models.FeedbackSubmissionRequest, userID string) (*models.FeedbackSubmissionResponse, error) {
	// Create feedback object
	feedback, err := models.NewFeedback(req, userID)
	if err != nil {
		log.Printf("Failed to create feedback: %v", err)
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Message: "Invalid feedback data",
			Error:   err.Error(),
		}, nil
	}

	// Sanitize feedback content
	feedback.Sanitize()

	// Convert to DynamoDB item
	item, err := feedback.ToDynamoDBItem()
	if err != nil {
		log.Printf("Failed to convert feedback to DynamoDB item: %v", err)
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Message: "Failed to process feedback",
			Error:   "Internal server error",
		}, err
	}

	// Store in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String(models.GetFeedbackTableName()),
		Item:      item,
	}

	_, err = fs.dynamoDB.PutItem(input)
	if err != nil {
		log.Printf("Failed to store feedback in DynamoDB: %v", err)
		return &models.FeedbackSubmissionResponse{
			Success: false,
			Message: "Failed to submit feedback",
			Error:   "Storage error",
		}, err
	}

	log.Printf("Successfully stored feedback with ID: %s", feedback.ID)

	return &models.FeedbackSubmissionResponse{
		Success:    true,
		FeedbackID: feedback.ID,
		Message:    "Feedback submitted successfully",
	}, nil
}

// GetFeedbackByUser retrieves feedback for a specific user
func (fs *FeedbackService) GetFeedbackByUser(userID string, limit int) (*models.FeedbackListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20 // Default limit
	}

	input := &dynamodb.QueryInput{
		TableName:              aws.String(models.GetFeedbackTableName()),
		IndexName:              aws.String(models.GetUserFeedbackGSIName()),
		KeyConditionExpression: aws.String("userId = :userId"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":userId": {
				S: aws.String(userID),
			},
		},
		ScanIndexForward: aws.Bool(false), // Sort by createdAt descending
		Limit:           aws.Int64(int64(limit)),
	}

	result, err := fs.dynamoDB.Query(input)
	if err != nil {
		log.Printf("Failed to query feedback by user: %v", err)
		return &models.FeedbackListResponse{
			Success: false,
			Error:   "Failed to retrieve feedback",
		}, err
	}

	var feedbackList []models.Feedback
	for _, item := range result.Items {
		var feedback models.Feedback
		err := feedback.FromDynamoDBItem(item)
		if err != nil {
			log.Printf("Failed to unmarshal feedback item: %v", err)
			continue
		}
		feedbackList = append(feedbackList, feedback)
	}

	return &models.FeedbackListResponse{
		Success:  true,
		Feedback: feedbackList,
		Count:    len(feedbackList),
	}, nil
}

// GetFeedbackByCategory retrieves feedback for a specific category
func (fs *FeedbackService) GetFeedbackByCategory(category models.FeedbackCategory, limit int) (*models.FeedbackListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 50 // Default limit
	}

	input := &dynamodb.QueryInput{
		TableName:              aws.String(models.GetFeedbackTableName()),
		IndexName:              aws.String(models.GetCategoryGSIName()),
		KeyConditionExpression: aws.String("category = :category"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":category": {
				S: aws.String(string(category)),
			},
		},
		ScanIndexForward: aws.Bool(false), // Sort by createdAt descending
		Limit:           aws.Int64(int64(limit)),
	}

	result, err := fs.dynamoDB.Query(input)
	if err != nil {
		log.Printf("Failed to query feedback by category: %v", err)
		return &models.FeedbackListResponse{
			Success: false,
			Error:   "Failed to retrieve feedback",
		}, err
	}

	var feedbackList []models.Feedback
	for _, item := range result.Items {
		var feedback models.Feedback
		err := feedback.FromDynamoDBItem(item)
		if err != nil {
			log.Printf("Failed to unmarshal feedback item: %v", err)
			continue
		}
		feedbackList = append(feedbackList, feedback)
	}

	return &models.FeedbackListResponse{
		Success:  true,
		Feedback: feedbackList,
		Count:    len(feedbackList),
	}, nil
}

// GetFeedbackStats retrieves feedback statistics
func (fs *FeedbackService) GetFeedbackStats() (*models.FeedbackStatsResponse, error) {
	// Scan all feedback items (in production, consider using aggregation tables)
	input := &dynamodb.ScanInput{
		TableName: aws.String(models.GetFeedbackTableName()),
	}

	result, err := fs.dynamoDB.Scan(input)
	if err != nil {
		log.Printf("Failed to scan feedback table: %v", err)
		return &models.FeedbackStatsResponse{
			Success: false,
			Error:   "Failed to retrieve feedback statistics",
		}, err
	}

	var feedbackList []models.Feedback
	totalRating := 0
	categoryBreakdown := make(map[models.FeedbackCategory]int)
	statusBreakdown := make(map[models.FeedbackStatus]int)

	for _, item := range result.Items {
		var feedback models.Feedback
		err := feedback.FromDynamoDBItem(item)
		if err != nil {
			log.Printf("Failed to unmarshal feedback item: %v", err)
			continue
		}

		feedbackList = append(feedbackList, feedback)
		totalRating += feedback.Rating
		categoryBreakdown[feedback.Category]++
		statusBreakdown[feedback.Status]++
	}

	// Calculate average rating
	var averageRating float64
	if len(feedbackList) > 0 {
		averageRating = float64(totalRating) / float64(len(feedbackList))
	}

	// Get recent feedback (last 10)
	sort.Slice(feedbackList, func(i, j int) bool {
		return feedbackList[i].CreatedAt.After(feedbackList[j].CreatedAt)
	})

	recentCount := 10
	if len(feedbackList) < recentCount {
		recentCount = len(feedbackList)
	}
	recentFeedback := feedbackList[:recentCount]

	return &models.FeedbackStatsResponse{
		Success:           true,
		TotalFeedback:     len(feedbackList),
		AverageRating:     averageRating,
		CategoryBreakdown: categoryBreakdown,
		StatusBreakdown:   statusBreakdown,
		RecentFeedback:    recentFeedback,
	}, nil
}

// GetFeedbackById retrieves a specific feedback by ID
func (fs *FeedbackService) GetFeedbackById(feedbackID string) (*models.Feedback, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(models.GetFeedbackTableName()),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
	}

	result, err := fs.dynamoDB.GetItem(input)
	if err != nil {
		log.Printf("Failed to get feedback by ID: %v", err)
		return nil, err
	}

	if result.Item == nil {
		return nil, fmt.Errorf("feedback not found")
	}

	var feedback models.Feedback
	err = feedback.FromDynamoDBItem(result.Item)
	if err != nil {
		log.Printf("Failed to unmarshal feedback item: %v", err)
		return nil, err
	}

	return &feedback, nil
}

// UpdateFeedbackStatus updates the status of feedback
func (fs *FeedbackService) UpdateFeedbackStatus(feedbackID string, status models.FeedbackStatus) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(models.GetFeedbackTableName()),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
		UpdateExpression: aws.String("SET #status = :status, updatedAt = :updatedAt"),
		ExpressionAttributeNames: map[string]*string{
			"#status": aws.String("status"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":status": {
				S: aws.String(string(status)),
			},
			":updatedAt": {
				S: aws.String(time.Now().Format(time.RFC3339)),
			},
		},
	}

	_, err := fs.dynamoDB.UpdateItem(input)
	if err != nil {
		log.Printf("Failed to update feedback status: %v", err)
		return err
	}

	return nil
}

// DeleteFeedback deletes feedback by ID
func (fs *FeedbackService) DeleteFeedback(feedbackID string) error {
	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(models.GetFeedbackTableName()),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(feedbackID),
			},
		},
	}

	_, err := fs.dynamoDB.DeleteItem(input)
	if err != nil {
		log.Printf("Failed to delete feedback: %v", err)
		return err
	}

	return nil
}

// GetRecentFeedback retrieves the most recent feedback
func (fs *FeedbackService) GetRecentFeedback(limit int) (*models.FeedbackListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20 // Default limit
	}

	// Since DynamoDB doesn't have a built-in way to sort by createdAt globally,
	// we'll scan and sort in memory (for production, consider using a GSI with createdAt)
	input := &dynamodb.ScanInput{
		TableName: aws.String(models.GetFeedbackTableName()),
	}

	result, err := fs.dynamoDB.Scan(input)
	if err != nil {
		log.Printf("Failed to scan feedback table: %v", err)
		return &models.FeedbackListResponse{
			Success: false,
			Error:   "Failed to retrieve recent feedback",
		}, err
	}

	var feedbackList []models.Feedback
	for _, item := range result.Items {
		var feedback models.Feedback
		err := feedback.FromDynamoDBItem(item)
		if err != nil {
			log.Printf("Failed to unmarshal feedback item: %v", err)
			continue
		}
		feedbackList = append(feedbackList, feedback)
	}

	// Sort by createdAt descending
	sort.Slice(feedbackList, func(i, j int) bool {
		return feedbackList[i].CreatedAt.After(feedbackList[j].CreatedAt)
	})

	// Limit results
	if len(feedbackList) > limit {
		feedbackList = feedbackList[:limit]
	}

	return &models.FeedbackListResponse{
		Success:  true,
		Feedback: feedbackList,
		Count:    len(feedbackList),
	}, nil
}

// CreateFeedbackTable creates the DynamoDB table for feedback (for setup/migration)
func (fs *FeedbackService) CreateFeedbackTable() error {
	input := &dynamodb.CreateTableInput{
		TableName: aws.String(models.GetFeedbackTableName()),
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String("HASH"),
			},
		},
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("userId"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("category"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("createdAt"),
				AttributeType: aws.String("S"),
			},
		},
		GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
			{
				IndexName: aws.String(models.GetUserFeedbackGSIName()),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("userId"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("createdAt"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String(models.GetCategoryGSIName()),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("category"),
						KeyType:       aws.String("HASH"),
					},
					{
						AttributeName: aws.String("createdAt"),
						KeyType:       aws.String("RANGE"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	}

	_, err := fs.dynamoDB.CreateTable(input)
	if err != nil {
		log.Printf("Failed to create feedback table: %v", err)
		return err
	}

	log.Printf("Successfully created feedback table: %s", models.GetFeedbackTableName())
	return nil
}