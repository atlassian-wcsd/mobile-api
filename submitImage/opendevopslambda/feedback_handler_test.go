package opendevopslambda

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"submit-image/models"
)

// MockDynamoDB is a mock implementation of DynamoDB interface
type MockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *MockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *MockDynamoDB) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func TestFeedbackHandler_HandleSubmitFeedback(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Valid feedback submission",
			requestBody: `{
				"rating": 5,
				"category": "general_feedback",
				"subject": "Great app!",
				"message": "I really love using this application. It's very intuitive and helpful.",
				"email": "user@example.com",
				"timestamp": "2023-01-01T00:00:00Z"
			}`,
			expectedStatus: 201,
			expectedError:  false,
		},
		{
			name: "Invalid rating",
			requestBody: `{
				"rating": 6,
				"category": "general_feedback",
				"subject": "Test",
				"message": "This is a test message",
				"timestamp": "2023-01-01T00:00:00Z"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Missing required fields",
			requestBody: `{
				"rating": 5,
				"category": "general_feedback"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Invalid category",
			requestBody: `{
				"rating": 5,
				"category": "invalid_category",
				"subject": "Test subject",
				"message": "This is a test message",
				"timestamp": "2023-01-01T00:00:00Z"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Subject too short",
			requestBody: `{
				"rating": 5,
				"category": "general_feedback",
				"subject": "Hi",
				"message": "This is a test message",
				"timestamp": "2023-01-01T00:00:00Z"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Message too short",
			requestBody: `{
				"rating": 5,
				"category": "general_feedback",
				"subject": "Test subject",
				"message": "Short",
				"timestamp": "2023-01-01T00:00:00Z"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock DynamoDB
			mockDB := new(MockDynamoDB)
			if !tt.expectedError {
				mockDB.On("PutItem", mock.AnythingOfType("*dynamodb.PutItemInput")).Return(
					&dynamodb.PutItemOutput{}, nil)
			}

			// Create handler
			handler := NewFeedbackHandler(mockDB)

			// Create request
			request := events.APIGatewayProxyRequest{
				Body: tt.requestBody,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			}

			// Execute
			response, err := handler.HandleSubmitFeedback(context.Background(), request)

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, response.StatusCode)

			// Parse response body
			var responseBody models.FeedbackSubmissionResponse
			err = json.Unmarshal([]byte(response.Body), &responseBody)
			assert.NoError(t, err)

			if tt.expectedError {
				assert.False(t, responseBody.Success)
				assert.NotEmpty(t, responseBody.Error)
			} else {
				assert.True(t, responseBody.Success)
				assert.NotEmpty(t, responseBody.FeedbackID)
				assert.Empty(t, responseBody.Error)
			}

			// Verify mock expectations
			if !tt.expectedError {
				mockDB.AssertExpectations(t)
			}
		})
	}
}

func TestFeedbackHandler_HandleOptions(t *testing.T) {
	// Setup
	mockDB := new(MockDynamoDB)
	handler := NewFeedbackHandler(mockDB)

	request := events.APIGatewayProxyRequest{
		HTTPMethod: "OPTIONS",
		Path:       "/feedback",
	}

	// Execute
	response, err := handler.HandleOptions(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Contains(t, response.Headers, "Access-Control-Allow-Origin")
	assert.Contains(t, response.Headers, "Access-Control-Allow-Methods")
	assert.Contains(t, response.Headers, "Access-Control-Allow-Headers")
}

func TestFeedbackValidator(t *testing.T) {
	handler := &FeedbackHandler{}

	tests := []struct {
		name        string
		request     models.FeedbackSubmissionRequest
		expectError bool
	}{
		{
			name: "Valid request",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Great app",
				Message:  "This is a detailed feedback message",
				Email:    "user@example.com",
			},
			expectError: false,
		},
		{
			name: "Invalid rating - too low",
			request: models.FeedbackSubmissionRequest{
				Rating:   0,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Test",
				Message:  "This is a test message",
			},
			expectError: true,
		},
		{
			name: "Invalid rating - too high",
			request: models.FeedbackSubmissionRequest{
				Rating:   6,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Test",
				Message:  "This is a test message",
			},
			expectError: true,
		},
		{
			name: "Invalid category",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: "invalid_category",
				Subject:  "Test",
				Message:  "This is a test message",
			},
			expectError: true,
		},
		{
			name: "Subject too short",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Hi",
				Message:  "This is a test message",
			},
			expectError: true,
		},
		{
			name: "Subject too long",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: models.CategoryGeneralFeedback,
				Subject:  string(make([]byte, 101)), // 101 characters
				Message:  "This is a test message",
			},
			expectError: true,
		},
		{
			name: "Message too short",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Test subject",
				Message:  "Short",
			},
			expectError: true,
		},
		{
			name: "Invalid email format",
			request: models.FeedbackSubmissionRequest{
				Rating:   5,
				Category: models.CategoryGeneralFeedback,
				Subject:  "Test subject",
				Message:  "This is a test message",
				Email:    "invalid-email",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateFeedbackRequest(&tt.request)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestModels_IsValidCategory(t *testing.T) {
	tests := []struct {
		category string
		expected bool
	}{
		{models.CategoryBugReport, true},
		{models.CategoryFeatureRequest, true},
		{models.CategoryGeneralFeedback, true},
		{models.CategorySupportRequest, true},
		{models.CategoryPerformanceIssue, true},
		{models.CategoryUIUXFeedback, true},
		{"invalid_category", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			result := models.IsValidCategory(tt.category)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModels_IsValidStatus(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{models.StatusSubmitted, true},
		{models.StatusInReview, true},
		{models.StatusResolved, true},
		{models.StatusClosed, true},
		{"invalid_status", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := models.IsValidStatus(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}