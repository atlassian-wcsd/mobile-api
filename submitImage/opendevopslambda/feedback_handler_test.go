package opendevopslambda

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
	"submit-image/models"
)

// Mock DynamoDB client for testing
type mockDynamoDBClient struct {
	dynamodbiface.DynamoDBAPI
	PutItemFunc   func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
	QueryFunc     func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
}

func (m *mockDynamoDBClient) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	if m.PutItemFunc != nil {
		return m.PutItemFunc(input)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoDBClient) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(input)
	}
	return &dynamodb.QueryOutput{}, nil
}

func TestHandleSubmitFeedback_Success(t *testing.T) {
	// Setup
	mockDB := &mockDynamoDBClient{
		PutItemFunc: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			assert.Equal(t, FeedbackTableName, *input.TableName)
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	handler := NewFeedbackHandler(mockDB)

	rating := 5
	feedbackReq := models.FeedbackSubmitRequest{
		FeedbackType: "bug",
		Rating:       &rating,
		Title:        "Test Bug Report",
		Message:      "This is a detailed test message about a bug I found.",
		Category:     "general",
		AllowContact: true,
		Email:        "test@example.com",
	}

	body, _ := json.Marshal(feedbackReq)

	request := events.APIGatewayProxyRequest{
		Body: string(body),
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Identity: events.APIGatewayRequestIdentity{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
			},
		},
	}

	// Execute
	response, err := handler.HandleSubmitFeedback(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	var respBody models.FeedbackSubmitResponse
	json.Unmarshal([]byte(response.Body), &respBody)
	assert.True(t, respBody.Success)
	assert.NotEmpty(t, respBody.FeedbackID)
}

func TestHandleSubmitFeedback_MissingAuth(t *testing.T) {
	// Setup
	handler := NewFeedbackHandler(&mockDynamoDBClient{})

	request := events.APIGatewayProxyRequest{
		Body:    `{"title":"Test","message":"Test message test","feedbackType":"bug","category":"general"}`,
		Headers: map[string]string{},
	}

	// Execute
	response, err := handler.HandleSubmitFeedback(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)
}

func TestHandleSubmitFeedback_InvalidRequest(t *testing.T) {
	// Setup
	handler := NewFeedbackHandler(&mockDynamoDBClient{})

	request := events.APIGatewayProxyRequest{
		Body: `invalid json`,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Identity: events.APIGatewayRequestIdentity{
				UserAgent: "Test Agent",
			},
		},
	}

	// Execute
	response, err := handler.HandleSubmitFeedback(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)
}

func TestHandleSubmitFeedback_ValidationError(t *testing.T) {
	// Setup
	handler := NewFeedbackHandler(&mockDynamoDBClient{})

	// Title too short
	feedbackReq := models.FeedbackSubmitRequest{
		FeedbackType: "bug",
		Title:        "ab", // Too short
		Message:      "This is a test message",
		Category:     "general",
	}

	body, _ := json.Marshal(feedbackReq)

	request := events.APIGatewayProxyRequest{
		Body: string(body),
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Identity: events.APIGatewayRequestIdentity{
				UserAgent: "Test Agent",
			},
		},
	}

	// Execute
	response, err := handler.HandleSubmitFeedback(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)
}

func TestHandleTrackMetric_Success(t *testing.T) {
	// Setup
	mockDB := &mockDynamoDBClient{
		PutItemFunc: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			assert.Equal(t, MetricsTableName, *input.TableName)
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	handler := NewFeedbackHandler(mockDB)

	metricReq := models.MetricTrackRequest{
		EventType: "action",
		EventName: "button_click",
		Properties: map[string]interface{}{
			"button_id": "submit",
		},
		SessionID: "test-session-123",
		Page:      "/home",
	}

	body, _ := json.Marshal(metricReq)

	request := events.APIGatewayProxyRequest{
		Body: string(body),
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Identity: events.APIGatewayRequestIdentity{
				UserAgent: "Mozilla/5.0",
			},
		},
	}

	// Execute
	response, err := handler.HandleTrackMetric(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	var respBody models.MetricTrackResponse
	json.Unmarshal([]byte(response.Body), &respBody)
	assert.True(t, respBody.Success)
	assert.NotEmpty(t, respBody.MetricID)
}

func TestHandleTrackMetric_MissingEventType(t *testing.T) {
	// Setup
	handler := NewFeedbackHandler(&mockDynamoDBClient{})

	metricReq := models.MetricTrackRequest{
		EventName: "button_click",
		// EventType missing
	}

	body, _ := json.Marshal(metricReq)

	request := events.APIGatewayProxyRequest{
		Body: string(body),
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Identity: events.APIGatewayRequestIdentity{
				UserAgent: "Test Agent",
			},
		},
	}

	// Execute
	response, err := handler.HandleTrackMetric(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)
}

func TestValidateFeedbackRequest(t *testing.T) {
	handler := &FeedbackHandler{}

	tests := []struct {
		name        string
		request     models.FeedbackSubmitRequest
		expectError bool
	}{
		{
			name: "Valid request",
			request: models.FeedbackSubmitRequest{
				FeedbackType: "bug",
				Title:        "Valid Title",
				Message:      "This is a valid message that is long enough",
				Category:     "general",
			},
			expectError: false,
		},
		{
			name: "Missing feedback type",
			request: models.FeedbackSubmitRequest{
				Title:    "Valid Title",
				Message:  "This is a valid message",
				Category: "general",
			},
			expectError: true,
		},
		{
			name: "Invalid feedback type",
			request: models.FeedbackSubmitRequest{
				FeedbackType: "invalid",
				Title:        "Valid Title",
				Message:      "This is a valid message",
				Category:     "general",
			},
			expectError: true,
		},
		{
			name: "Title too short",
			request: models.FeedbackSubmitRequest{
				FeedbackType: "bug",
				Title:        "ab",
				Message:      "This is a valid message",
				Category:     "general",
			},
			expectError: true,
		},
		{
			name: "Message too short",
			request: models.FeedbackSubmitRequest{
				FeedbackType: "bug",
				Title:        "Valid Title",
				Message:      "short",
				Category:     "general",
			},
			expectError: true,
		},
		{
			name: "Invalid rating",
			request: models.FeedbackSubmitRequest{
				FeedbackType: "bug",
				Title:        "Valid Title",
				Message:      "This is a valid message",
				Category:     "general",
				Rating:       func() *int { r := 6; return &r }(),
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

func TestExtractDeviceInfo(t *testing.T) {
	handler := &FeedbackHandler{}

	tests := []struct {
		name          string
		userAgent     string
		expectedMobile bool
		expectedPlatform string
		expectedBrowser  string
	}{
		{
			name:          "Windows Chrome",
			userAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			expectedMobile: false,
			expectedPlatform: "Windows",
			expectedBrowser:  "Chrome",
		},
		{
			name:          "iPhone Safari",
			userAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			expectedMobile: true,
			expectedPlatform: "iOS",
			expectedBrowser:  "Safari",
		},
		{
			name:          "Android Chrome",
			userAgent:     "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
			expectedMobile: true,
			expectedPlatform: "Android",
			expectedBrowser:  "Chrome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceInfo := handler.extractDeviceInfo(tt.userAgent)
			assert.Equal(t, tt.expectedMobile, deviceInfo.IsMobile)
			assert.Equal(t, tt.expectedPlatform, deviceInfo.Platform)
			assert.Equal(t, tt.expectedBrowser, deviceInfo.Browser)
		})
	}
}
