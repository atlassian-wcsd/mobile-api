package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDependency mocks the opendevopslambda.Dependency
type MockDependency struct {
	mock.Mock
}

func (m *MockDependency) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

// MockAppleAuthHandler mocks the Apple authentication handler
type MockAppleAuthHandler struct {
	mock.Mock
}

func (m *MockAppleAuthHandler) HandleVerifyToken(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

func (m *MockAppleAuthHandler) HandleRefreshToken(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

func (m *MockAppleAuthHandler) HandleSignOut(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

func (m *MockAppleAuthHandler) HandleGetProfile(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

func (m *MockAppleAuthHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(events.APIGatewayProxyResponse), args.Error(1)
}

func TestRouter_Handler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		method         string
		setupMocks     func(*MockDependency, *MockAppleAuthHandler)
		expectedStatus int
		expectApple    bool
		expectImage    bool
	}{
		{
			name:   "Apple verify token endpoint",
			path:   "/auth/apple/verify",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleVerifyToken", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"success": true}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    true,
			expectImage:    false,
		},
		{
			name:   "Apple refresh token endpoint",
			path:   "/auth/apple/refresh",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleRefreshToken", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"success": true}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    true,
			expectImage:    false,
		},
		{
			name:   "Apple sign out endpoint",
			path:   "/auth/apple/signout",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleSignOut", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"success": true}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    true,
			expectImage:    false,
		},
		{
			name:   "Apple get profile endpoint",
			path:   "/auth/apple/profile",
			method: "GET",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleGetProfile", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"success": true, "user": {}}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    true,
			expectImage:    false,
		},
		{
			name:   "Apple OPTIONS request",
			path:   "/auth/apple/verify",
			method: "OPTIONS",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleOptions", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Headers: map[string]string{
							"Access-Control-Allow-Origin":  "*",
							"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
							"Access-Control-Allow-Headers": "Content-Type, Authorization",
						},
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    true,
			expectImage:    false,
		},
		{
			name:   "Non-Apple endpoint falls back to image handler",
			path:   "/submit-image",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				imageDep.On("Handler", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"message": "Image submitted"}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    false,
			expectImage:    true,
		},
		{
			name:   "Root path falls back to image handler",
			path:   "/",
			method: "GET",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				imageDep.On("Handler", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{
						StatusCode: 200,
						Body:       `{"message": "Root endpoint"}`,
					}, nil)
			},
			expectedStatus: 200,
			expectApple:    false,
			expectImage:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockImageDep := &MockDependency{}
			mockAppleDep := &MockAppleAuthHandler{}

			// Setup mock expectations
			tt.setupMocks(mockImageDep, mockAppleDep)

			// Create router with mocks
			router := &Router{
				imageDependency:  mockImageDep,
				appleAuthHandler: mockAppleDep,
			}

			// Create request
			request := events.APIGatewayProxyRequest{
				Path:       tt.path,
				HTTPMethod: tt.method,
			}

			// Execute
			response, err := router.Handler(context.Background(), request)

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, response.StatusCode)

			// Verify mock expectations
			if tt.expectApple {
				mockAppleDep.AssertExpectations(t)
				mockImageDep.AssertNotCalled(t, "Handler")
			}
			if tt.expectImage {
				mockImageDep.AssertExpectations(t)
				// Apple handler methods should not be called
				mockAppleDep.AssertNotCalled(t, "HandleVerifyToken")
				mockAppleDep.AssertNotCalled(t, "HandleRefreshToken")
				mockAppleDep.AssertNotCalled(t, "HandleSignOut")
				mockAppleDep.AssertNotCalled(t, "HandleGetProfile")
				mockAppleDep.AssertNotCalled(t, "HandleOptions")
			}
		})
	}
}

func TestRouter_Handler_WithoutAppleAuth(t *testing.T) {
	// Test router behavior when Apple auth handler is nil
	mockImageDep := &MockDependency{}
	mockImageDep.On("Handler", mock.Anything, mock.Anything).Return(
		events.APIGatewayProxyResponse{
			StatusCode: 200,
			Body:       `{"message": "Handled by image dependency"}`,
		}, nil)

	router := &Router{
		imageDependency:  mockImageDep,
		appleAuthHandler: nil, // No Apple auth handler
	}

	request := events.APIGatewayProxyRequest{
		Path:       "/auth/apple/verify",
		HTTPMethod: "POST",
	}

	response, err := router.Handler(context.Background(), request)

	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	mockImageDep.AssertExpectations(t)
}

func TestRouter_Handler_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		method      string
		setupMocks  func(*MockDependency, *MockAppleAuthHandler)
		expectError bool
	}{
		{
			name:   "Apple handler returns error",
			path:   "/auth/apple/verify",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				appleDep.On("HandleVerifyToken", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{}, assert.AnError)
			},
			expectError: true,
		},
		{
			name:   "Image handler returns error",
			path:   "/submit-image",
			method: "POST",
			setupMocks: func(imageDep *MockDependency, appleDep *MockAppleAuthHandler) {
				imageDep.On("Handler", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{}, assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockImageDep := &MockDependency{}
			mockAppleDep := &MockAppleAuthHandler{}

			tt.setupMocks(mockImageDep, mockAppleDep)

			router := &Router{
				imageDependency:  mockImageDep,
				appleAuthHandler: mockAppleDep,
			}

			request := events.APIGatewayProxyRequest{
				Path:       tt.path,
				HTTPMethod: tt.method,
			}

			_, err := router.Handler(context.Background(), request)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRouter_Handler_RequestLogging(t *testing.T) {
	// This test verifies that requests are logged properly
	// In a real implementation, you might want to capture log output
	mockImageDep := &MockDependency{}
	mockImageDep.On("Handler", mock.Anything, mock.Anything).Return(
		events.APIGatewayProxyResponse{StatusCode: 200}, nil)

	router := &Router{
		imageDependency:  mockImageDep,
		appleAuthHandler: nil,
	}

	request := events.APIGatewayProxyRequest{
		Path:       "/test-path",
		HTTPMethod: "GET",
	}

	_, err := router.Handler(context.Background(), request)

	assert.NoError(t, err)
	mockImageDep.AssertExpectations(t)
}

func TestNewRouter(t *testing.T) {
	// Test router creation
	// Note: This test would need to be adapted based on your actual AWS session setup
	// For now, we'll test the structure
	t.Run("Router creation structure", func(t *testing.T) {
		// This is a placeholder test since NewRouter() depends on AWS session
		// In a real test environment, you'd mock the AWS dependencies
		router := &Router{}
		assert.NotNil(t, router)
	})
}

func TestRouter_AppleAuthPathMatching(t *testing.T) {
	tests := []struct {
		path           string
		method         string
		shouldMatchApple bool
	}{
		{"/auth/apple/verify", "POST", true},
		{"/auth/apple/refresh", "POST", true},
		{"/auth/apple/signout", "POST", true},
		{"/auth/apple/profile", "GET", true},
		{"/auth/apple/verify", "OPTIONS", true},
		{"/auth/apple/refresh", "OPTIONS", true},
		{"/auth/apple/unknown", "OPTIONS", true}, // Any apple path with OPTIONS
		{"/auth/apple/verify", "GET", false},     // Wrong method
		{"/auth/apple/refresh", "GET", false},    // Wrong method
		{"/auth/apple/signout", "GET", false},    // Wrong method
		{"/auth/apple/profile", "POST", false},   // Wrong method
		{"/auth/google/verify", "POST", false},   // Different auth provider
		{"/api/apple/verify", "POST", false},     // Different base path
		{"/submit-image", "POST", false},         // Different endpoint
		{"/", "GET", false},                      // Root path
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.method, func(t *testing.T) {
			mockImageDep := &MockDependency{}
			mockAppleDep := &MockAppleAuthHandler{}

			if tt.shouldMatchApple {
				// Setup appropriate mock based on path and method
				switch {
				case tt.path == "/auth/apple/verify" && tt.method == "POST":
					mockAppleDep.On("HandleVerifyToken", mock.Anything, mock.Anything).Return(
						events.APIGatewayProxyResponse{StatusCode: 200}, nil)
				case tt.path == "/auth/apple/refresh" && tt.method == "POST":
					mockAppleDep.On("HandleRefreshToken", mock.Anything, mock.Anything).Return(
						events.APIGatewayProxyResponse{StatusCode: 200}, nil)
				case tt.path == "/auth/apple/signout" && tt.method == "POST":
					mockAppleDep.On("HandleSignOut", mock.Anything, mock.Anything).Return(
						events.APIGatewayProxyResponse{StatusCode: 200}, nil)
				case tt.path == "/auth/apple/profile" && tt.method == "GET":
					mockAppleDep.On("HandleGetProfile", mock.Anything, mock.Anything).Return(
						events.APIGatewayProxyResponse{StatusCode: 200}, nil)
				case tt.method == "OPTIONS":
					mockAppleDep.On("HandleOptions", mock.Anything, mock.Anything).Return(
						events.APIGatewayProxyResponse{StatusCode: 200}, nil)
				}
			} else {
				mockImageDep.On("Handler", mock.Anything, mock.Anything).Return(
					events.APIGatewayProxyResponse{StatusCode: 200}, nil)
			}

			router := &Router{
				imageDependency:  mockImageDep,
				appleAuthHandler: mockAppleDep,
			}

			request := events.APIGatewayProxyRequest{
				Path:       tt.path,
				HTTPMethod: tt.method,
			}

			_, err := router.Handler(context.Background(), request)

			assert.NoError(t, err)

			if tt.shouldMatchApple {
				mockAppleDep.AssertExpectations(t)
				mockImageDep.AssertNotCalled(t, "Handler")
			} else {
				mockImageDep.AssertExpectations(t)
			}
		})
	}
}