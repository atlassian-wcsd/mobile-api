package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"submit-image/models"
)

// MockDynamoDBAPI is a mock implementation of DynamoDB API
type MockDynamoDBAPI struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *MockDynamoDBAPI) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *MockDynamoDBAPI) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func (m *MockDynamoDBAPI) Scan(input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.ScanOutput), args.Error(1)
}

func TestFeedbackHandler_HandleFeedbackSubmission(t *testing.T) {
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
				"feedbackText": "This is a great app! I love using it.",
				"category": "general_feedback",
				"contactEmail": "user@example.com"
			}`,
			expectedStatus: 200,
			expectedError:  false,
		},
		{
			name: "Invalid rating",
			requestBody: `{
				"rating": 6,
				"feedbackText": "This is feedback with invalid rating.",
				"category": "general_feedback"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Missing feedback text",
			requestBody: `{
				"rating": 4,
				"category": "general_feedback"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Feedback text too short",
			requestBody: `{
				"rating": 4,
				"feedbackText": "Short",
				"category": "general_feedback"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Invalid email format",
			requestBody: `{
				"rating": 4,
				"feedbackText": "This is valid feedback text.",
				"category": "general_feedback",
				"contactEmail": "invalid-email"
			}`,
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name: "Invalid JSON",
			requestBody: `{
				"rating": 4,
				"feedbackText": "Valid feedback",
				"category": "general_feedback"
			`,
			expectedStatus: 400,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock DynamoDB
			mockDB := new(MockDynamoDBAPI)
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

			// Execute handler
			response, err := handler.HandleFeedbackSubmission(context.Background(), request)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, response.StatusCode)

			// Parse response body
			var responseBody map[string]interface{}
			err = json.Unmarshal([]byte(response.Body), &responseBody)
			assert.NoError(t, err)

			if tt.expectedError {
				assert.False(t, responseBody["success"].(bool))
				assert.NotEmpty(t, responseBody["error"])
			} else {
				assert.True(t, responseBody["success"].(bool))
				assert.NotEmpty(t, responseBody["feedbackId"])
				assert.NotEmpty(t, responseBody["message"])
			}

			// Verify CORS headers
			assert.Equal(t, "*", response.Headers["Access-Control-Allow-Origin"])
			assert.Equal(t, "application/json", response.Headers["Content-Type"])

			mockDB.AssertExpectations(t)
		})
	}
}

func TestFeedbackHandler_HandleFeedbackHistory(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Valid authenticated request",
			headers: map[string]string{
				"Authorization": "Bearer valid-token",
			},
			expectedStatus: 200,
			expectedError:  false,
		},
		{
			name:           "Missing authentication",
			headers:        map[string]string{},
			expectedStatus: 401,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock DynamoDB
			mockDB := new(MockDynamoDBAPI)
			if !tt.expectedError {
				mockDB.On("Query", mock.AnythingOfType("*dynamodb.QueryInput")).Return(
					&dynamodb.QueryOutput{
						Items: []map[string]*dynamodb.AttributeValue{},
					}, nil)
			}

			// Create handler
			handler := NewFeedbackHandler(mockDB)

			// Create request
			request := events.APIGatewayProxyRequest{
				Headers: tt.headers,
			}

			// Execute handler
			response, err := handler.HandleFeedbackHistory(context.Background(), request)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, response.StatusCode)

			// Parse response body
			var responseBody map[string]interface{}
			err = json.Unmarshal([]byte(response.Body), &responseBody)
			assert.NoError(t, err)

			if tt.expectedError {
				assert.False(t, responseBody["success"].(bool))
				assert.NotEmpty(t, responseBody["error"])
			} else {
				assert.True(t, responseBody["success"].(bool))
				assert.Contains(t, responseBody, "feedback")
				assert.Contains(t, responseBody, "count")
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestFeedbackHandler_HandleFeedbackStats(t *testing.T) {
	// Setup mock DynamoDB
	mockDB := new(MockDynamoDBAPI)
	mockDB.On("Scan", mock.AnythingOfType("*dynamodb.ScanInput")).Return(
		&dynamodb.ScanOutput{
			Items: []map[string]*dynamodb.AttributeValue{},
		}, nil)

	// Create handler
	handler := NewFeedbackHandler(mockDB)

	// Create request with authentication
	request := events.APIGatewayProxyRequest{
		Headers: map[string]string{
			"Authorization": "Bearer valid-token",
		},
	}

	// Execute handler
	response, err := handler.HandleFeedbackStats(context.Background(), request)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &responseBody)
	assert.NoError(t, err)

	assert.True(t, responseBody["success"].(bool))
	assert.Contains(t, responseBody, "totalFeedback")
	assert.Contains(t, responseBody, "averageRating")
	assert.Contains(t, responseBody, "categoryBreakdown")
	assert.Contains(t, responseBody, "statusBreakdown")
	assert.Contains(t, responseBody, "recentFeedback")

	mockDB.AssertExpectations(t)
}

func TestFeedbackHandler_HandleFeedbackByCategory(t *testing.T) {
	tests := []struct {
		name           string
		pathParams     map[string]string
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "Valid category",
			pathParams: map[string]string{
				"category": "bug_report",
			},
			expectedStatus: 200,
			expectedError:  false,
		},
		{
			name: "Invalid category",
			pathParams: map[string]string{
				"category": "invalid_category",
			},
			expectedStatus: 400,
			expectedError:  true,
		},
		{
			name:           "Missing category",
			pathParams:     map[string]string{},
			expectedStatus: 400,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock DynamoDB
			mockDB := new(MockDynamoDBAPI)
			if !tt.expectedError {
				mockDB.On("Query", mock.AnythingOfType("*dynamodb.QueryInput")).Return(
					&dynamodb.QueryOutput{
						Items: []map[string]*dynamodb.AttributeValue{},
					}, nil)
			}

			// Create handler
			handler := NewFeedbackHandler(mockDB)

			// Create request
			request := events.APIGatewayProxyRequest{
				PathParameters: tt.pathParams,
			}

			// Execute handler
			response, err := handler.HandleFeedbackByCategory(context.Background(), request)

			// Assertions
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, response.StatusCode)

			// Parse response body
			var responseBody map[string]interface{}
			err = json.Unmarshal([]byte(response.Body), &responseBody)
			assert.NoError(t, err)

			if tt.expectedError {
				assert.False(t, responseBody["success"].(bool))
				assert.NotEmpty(t, responseBody["error"])
			} else {
				assert.True(t, responseBody["success"].(bool))
				assert.Contains(t, responseBody, "feedback")
				assert.Contains(t, responseBody, "count")
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestFeedbackHandler_HandleHealthCheck(t *testing.T) {
	// Create handler (no DynamoDB needed for health check)
	handler := NewFeedbackHandler(nil)

	// Create request
	request := events.APIGatewayProxyRequest{
		RequestContext: events.APIGatewayProxyRequestContext{
			RequestTimeEpoch: 1640995200000,
		},
	}

	// Execute handler
	response, err := handler.HandleHealthCheck(context.Background(), request)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &responseBody)
	assert.NoError(t, err)

	assert.Equal(t, "healthy", responseBody["status"])
	assert.Equal(t, "feedback", responseBody["service"])
	assert.Contains(t, responseBody, "timestamp")

	// Verify CORS headers
	assert.Equal(t, "*", response.Headers["Access-Control-Allow-Origin"])
	assert.Equal(t, "application/json", response.Headers["Content-Type"])
}

func TestFeedbackHandler_HandleFeedbackOptions(t *testing.T) {
	// Create handler
	handler := NewFeedbackHandler(nil)

	// Create request
	request := events.APIGatewayProxyRequest{}

	// Execute handler
	response, err := handler.HandleFeedbackOptions(context.Background(), request)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Empty(t, response.Body)

	// Verify CORS headers
	assert.Equal(t, "*", response.Headers["Access-Control-Allow-Origin"])
	assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", response.Headers["Access-Control-Allow-Methods"])
	assert.Equal(t, "Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token", response.Headers["Access-Control-Allow-Headers"])
}