package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"submit-image/models"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock DynamoDB client
type mockDynamoDBClient struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDBClient) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *mockDynamoDBClient) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func (m *mockDynamoDBClient) Scan(input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.ScanOutput), args.Error(1)
}

// Mock SES client
type mockSESClient struct {
	sesiface.SESAPI
	mock.Mock
}

func (m *mockSESClient) SendEmail(input *ses.SendEmailInput) (*ses.SendEmailOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*ses.SendEmailOutput), args.Error(1)
}

func TestHandleRegister_Success(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Mock DynamoDB responses for username/email existence checks
	mockDynamoDB.On("Query", mock.AnythingOfType("*dynamodb.QueryInput")).Return(
		&dynamodb.QueryOutput{Items: []map[string]*dynamodb.AttributeValue{}}, nil,
	)

	// Mock DynamoDB response for user creation
	mockDynamoDB.On("PutItem", mock.AnythingOfType("*dynamodb.PutItemInput")).Return(
		&dynamodb.PutItemOutput{}, nil,
	)

	// Mock SES response for email sending
	mockSES.On("SendEmail", mock.AnythingOfType("*ses.SendEmailInput")).Return(
		&ses.SendEmailOutput{}, nil,
	)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "test@example.com",
		Password:        "TestPass123!",
		ConfirmPassword: "TestPass123!",
		FirstName:       "Test",
		LastName:        "User",
		TermsAccepted:   true,
		PrivacyAccepted: true,
		CaptchaToken:    "test-token", // This will work with our test captcha service
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 201, response.StatusCode)

	var respBody models.UserRegistrationResponse
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.True(t, respBody.Success)
	assert.Contains(t, respBody.Message, "Registration successful")
	assert.NotEmpty(t, respBody.UserID)

	// Verify mocks were called
	mockDynamoDB.AssertExpectations(t)
	mockSES.AssertExpectations(t)
}

func TestHandleRegister_InvalidPassword(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request with weak password
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "test@example.com",
		Password:        "weak", // Too weak
		ConfirmPassword: "weak",
		TermsAccepted:   true,
		PrivacyAccepted: true,
		CaptchaToken:    "test-token",
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)

	var respBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["success"].(bool))
	assert.Contains(t, respBody["error"].(string), "password must be at least 8 characters")
}

func TestHandleRegister_PasswordMismatch(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request with mismatched passwords
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "test@example.com",
		Password:        "TestPass123!",
		ConfirmPassword: "DifferentPass123!",
		TermsAccepted:   true,
		PrivacyAccepted: true,
		CaptchaToken:    "test-token",
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)

	var respBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["success"].(bool))
	assert.Contains(t, respBody["error"].(string), "passwords do not match")
}

func TestHandleRegister_InvalidEmail(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request with invalid email
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "invalid-email",
		Password:        "TestPass123!",
		ConfirmPassword: "TestPass123!",
		TermsAccepted:   true,
		PrivacyAccepted: true,
		CaptchaToken:    "test-token",
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)

	var respBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["success"].(bool))
	assert.Contains(t, respBody["error"].(string), "invalid email format")
}

func TestHandleRegister_TermsNotAccepted(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request without accepting terms
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "test@example.com",
		Password:        "TestPass123!",
		ConfirmPassword: "TestPass123!",
		TermsAccepted:   false, // Not accepted
		PrivacyAccepted: true,
		CaptchaToken:    "test-token",
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)

	var respBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["success"].(bool))
	assert.Contains(t, respBody["error"].(string), "must accept the terms and conditions")
}

func TestHandleRegister_InvalidCaptcha(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request with invalid captcha
	regReq := models.UserRegistrationRequest{
		Username:        "testuser",
		Email:           "test@example.com",
		Password:        "TestPass123!",
		ConfirmPassword: "TestPass123!",
		TermsAccepted:   true,
		PrivacyAccepted: true,
		CaptchaToken:    "invalid-token", // Invalid token
	}

	reqBody, _ := json.Marshal(regReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleRegister(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 400, response.StatusCode)

	var respBody map[string]interface{}
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.False(t, respBody["success"].(bool))
	assert.Contains(t, respBody["error"].(string), "CAPTCHA verification failed")
}

func TestHandleVerifyEmail_Success(t *testing.T) {
	// Setup mocks
	mockDynamoDB := new(mockDynamoDBClient)
	mockSES := new(mockSESClient)

	// Mock DynamoDB response for finding user by token
	mockDynamoDB.On("Scan", mock.AnythingOfType("*dynamodb.ScanInput")).Return(
		&dynamodb.ScanOutput{
			Items: []map[string]*dynamodb.AttributeValue{
				{
					"id": {S: aws.String("user-123")},
					"email": {S: aws.String("test@example.com")},
					"email_verify_token": {S: aws.String("valid-token")},
				},
			},
		}, nil,
	)

	// Mock DynamoDB response for updating user
	mockDynamoDB.On("PutItem", mock.AnythingOfType("*dynamodb.PutItemInput")).Return(
		&dynamodb.PutItemOutput{}, nil,
	)

	// Create handler
	handler := NewUserRegistrationHandler(mockDynamoDB, mockSES)

	// Create test request
	verifyReq := models.EmailVerificationRequest{
		Token: "valid-token",
	}

	reqBody, _ := json.Marshal(verifyReq)
	request := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	// Execute
	response, err := handler.HandleVerifyEmail(context.Background(), request)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	var respBody models.EmailVerificationResponse
	err = json.Unmarshal([]byte(response.Body), &respBody)
	assert.NoError(t, err)
	assert.True(t, respBody.Success)
	assert.Contains(t, respBody.Message, "Email verified successfully")

	// Verify mocks were called
	mockDynamoDB.AssertExpectations(t)
}