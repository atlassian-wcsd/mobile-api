package opendevopslambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

// Dependency holds injectable AWS service clients
type Dependency struct {
	DepDynamoDB dynamodbiface.DynamoDBAPI
}

// FeedbackRequest represents the incoming feedback submission payload
type FeedbackRequest struct {
	UserID       string            `json:"userId"`
	Category     string            `json:"category"`
	Rating       int               `json:"rating"`
	Message      string            `json:"message"`
	ContactEmail string            `json:"contactEmail,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// FeedbackResponse represents the API response after feedback submission
type FeedbackResponse struct {
	FeedbackID string `json:"feedbackId"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

var feedbackTableName = "UserFeedback"

var validCategories = map[string]bool{
	"bug":             true,
	"feature_request": true,
	"improvement":     true,
	"general":         true,
}

// validateFeedbackRequest validates the incoming feedback payload
func validateFeedbackRequest(req FeedbackRequest) error {
	if strings.TrimSpace(req.UserID) == "" {
		return errors.New("userId is required")
	}

	if !validCategories[req.Category] {
		return errors.New("invalid category: must be one of bug, feature_request, improvement, general")
	}

	if req.Rating < 1 || req.Rating > 5 {
		return errors.New("rating must be between 1 and 5")
	}

	trimmedMessage := strings.TrimSpace(req.Message)
	if len(trimmedMessage) == 0 {
		return errors.New("message is required")
	}
	if len(trimmedMessage) > 2000 {
		return errors.New("message must not exceed 2000 characters")
	}

	if req.ContactEmail != "" && !isValidEmail(req.ContactEmail) {
		return errors.New("invalid email format")
	}

	return nil
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	atIndex := strings.Index(email, "@")
	if atIndex < 1 {
		return false
	}
	domain := email[atIndex+1:]
	dotIndex := strings.LastIndex(domain, ".")
	if dotIndex < 1 || dotIndex >= len(domain)-1 {
		return false
	}
	return !strings.Contains(email, " ")
}

// sanitizeInput escapes HTML special characters to prevent XSS
func sanitizeInput(input string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
	)
	return replacer.Replace(input)
}

// storeFeedback persists the feedback to DynamoDB
func (d *Dependency) storeFeedback(feedbackID string, req FeedbackRequest, region string) error {
	item := map[string]*dynamodb.AttributeValue{
		"Id": {
			S: aws.String(feedbackID),
		},
		"UserId": {
			S: aws.String(req.UserID),
		},
		"Category": {
			S: aws.String(req.Category),
		},
		"Rating": {
			N: aws.String(fmt.Sprintf("%d", req.Rating)),
		},
		"Message": {
			S: aws.String(sanitizeInput(req.Message)),
		},
		"CreatedAt": {
			S: aws.String(time.Now().UTC().Format(time.RFC3339)),
		},
		"Region": {
			S: aws.String(region),
		},
		"Status": {
			S: aws.String("submitted"),
		},
	}

	if req.ContactEmail != "" {
		item["ContactEmail"] = &dynamodb.AttributeValue{
			S: aws.String(req.ContactEmail),
		}
	}

	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err == nil {
			item["Metadata"] = &dynamodb.AttributeValue{
				S: aws.String(string(metadataJSON)),
			}
		}
	}

	input := &dynamodb.PutItemInput{
		Item:      item,
		TableName: aws.String(feedbackTableName),
	}

	_, err := d.DepDynamoDB.PutItem(input)
	return err
}

// Handler is the Lambda entry point for feedback submission
func (d *Dependency) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]

	// Set CORS headers
	headers := map[string]string{
		"Content-Type":                "application/json",
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Headers": "Content-Type",
		"Access-Control-Allow-Methods": "POST,OPTIONS",
	}

	// Handle CORS preflight
	if request.HTTPMethod == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Headers:    headers,
			Body:       "",
		}, nil
	}

	// Parse request body
	var feedbackReq FeedbackRequest
	if err := json.Unmarshal([]byte(request.Body), &feedbackReq); err != nil {
		respBody, _ := json.Marshal(FeedbackResponse{
			Status:  "error",
			Message: "Invalid request body",
		})
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       string(respBody),
		}, nil
	}

	// Validate request
	if err := validateFeedbackRequest(feedbackReq); err != nil {
		respBody, _ := json.Marshal(FeedbackResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       string(respBody),
		}, nil
	}

	// Generate feedback ID
	feedbackID, uuidErr := uuid.NewRandom()
	if uuidErr != nil {
		respBody, _ := json.Marshal(FeedbackResponse{
			Status:  "error",
			Message: "Failed to generate feedback ID",
		})
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Headers:    headers,
			Body:       string(respBody),
		}, uuidErr
	}

	// Store feedback in DynamoDB
	if err := d.storeFeedback(feedbackID.String(), feedbackReq, region); err != nil {
		respBody, _ := json.Marshal(FeedbackResponse{
			Status:  "error",
			Message: "Failed to store feedback",
		})
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Headers:    headers,
			Body:       string(respBody),
		}, err
	}

	// Return success response
	respBody, _ := json.Marshal(FeedbackResponse{
		FeedbackID: feedbackID.String(),
		Status:     "submitted",
		Message:    "Feedback submitted successfully",
	})
	return events.APIGatewayProxyResponse{
		StatusCode: 201,
		Headers:    headers,
		Body:       string(respBody),
	}, nil
}
