package userauth

import (
	"testing"
	"time"

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

func (m *mockDynamoDBClient) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func (m *mockDynamoDBClient) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *mockDynamoDBClient) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
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

func TestUserRegistrationRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request UserRegistrationRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "TestPass123!",
				Email:    "test@example.com",
				FullName: "Test User",
			},
			wantErr: false,
		},
		{
			name: "username too short",
			request: UserRegistrationRequest{
				Username: "ab",
				Password: "TestPass123!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "username must be at least 3 characters long",
		},
		{
			name: "username too long",
			request: UserRegistrationRequest{
				Username: "verylongusernamethatexceedslimit",
				Password: "TestPass123!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "username must be less than 20 characters long",
		},
		{
			name: "invalid username characters",
			request: UserRegistrationRequest{
				Username: "test@user",
				Password: "TestPass123!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "username can only contain letters, numbers, underscores, and hyphens",
		},
		{
			name: "password too short",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "short",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "password must be at least 8 characters long",
		},
		{
			name: "password missing uppercase",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "testpass123!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "password must contain at least one uppercase letter",
		},
		{
			name: "password missing lowercase",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "TESTPASS123!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "password must contain at least one lowercase letter",
		},
		{
			name: "password missing number",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "TestPass!",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "password must contain at least one number",
		},
		{
			name: "password missing special character",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "TestPass123",
				Email:    "test@example.com",
			},
			wantErr: true,
			errMsg:  "password must contain at least one special character",
		},
		{
			name: "invalid email format",
			request: UserRegistrationRequest{
				Username: "testuser",
				Password: "TestPass123!",
				Email:    "invalid-email",
			},
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name: "invalid phone number",
			request: UserRegistrationRequest{
				Username:    "testuser",
				Password:    "TestPass123!",
				Email:       "test@example.com",
				PhoneNumber: "abc123",
			},
			wantErr: true,
			errMsg:  "phone number must contain 10-15 digits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationErrors := tt.request.Validate()
			
			if tt.wantErr {
				assert.NotNil(t, validationErrors)
				assert.Greater(t, len(validationErrors.Errors), 0)
				
				// Check if the expected error message is present
				found := false
				for _, err := range validationErrors.Errors {
					if err.Message == tt.errMsg {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected error message not found: %s", tt.errMsg)
			} else {
				assert.Nil(t, validationErrors)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid username", "testuser", false},
		{"valid with underscore", "test_user", false},
		{"valid with hyphen", "test-user", false},
		{"valid with numbers", "testuser123", false},
		{"too short", "ab", true},
		{"too long", "verylongusernamethatexceedslimit", true},
		{"starts with underscore", "_testuser", true},
		{"ends with underscore", "testuser_", true},
		{"starts with hyphen", "-testuser", true},
		{"ends with hyphen", "testuser-", true},
		{"contains special chars", "test@user", true},
		{"contains spaces", "test user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "TestPass123!", false},
		{"valid with symbols", "MyP@ssw0rd#", false},
		{"too short", "Test1!", true},
		{"missing uppercase", "testpass123!", true},
		{"missing lowercase", "TESTPASS123!", true},
		{"missing number", "TestPass!", true},
		{"missing special", "TestPass123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid with subdomain", "test@mail.example.com", false},
		{"valid with plus", "test+tag@example.com", false},
		{"empty email", "", true},
		{"missing @", "testexample.com", true},
		{"missing domain", "test@", true},
		{"missing local part", "@example.com", true},
		{"invalid format", "test@", true},
		{"no TLD", "test@example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmail(tt.email)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePhoneNumber(t *testing.T) {
	tests := []struct {
		name  string
		phone string
		valid bool
	}{
		{"valid US number", "1234567890", true},
		{"valid with country code", "12345678901", true},
		{"valid with formatting", "(123) 456-7890", true},
		{"valid with spaces", "123 456 7890", true},
		{"valid with dashes", "123-456-7890", true},
		{"valid with plus", "+1234567890", true},
		{"empty (optional)", "", true},
		{"too short", "123456789", false},
		{"too long", "1234567890123456", false},
		{"contains letters", "123abc7890", false},
		{"contains symbols", "123*456*7890", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePhoneNumber(tt.phone)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestUserService_hashPassword(t *testing.T) {
	mockDynamoDB := &mockDynamoDBClient{}
	mockSES := &mockSESClient{}
	service := NewUserService(mockDynamoDB, mockSES, "test@example.com", "https://example.com")

	password := "TestPassword123!"
	hash1, salt1, err1 := service.hashPassword(password)
	assert.NoError(t, err1)
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, salt1)

	// Hash the same password again - should get different hash and salt
	hash2, salt2, err2 := service.hashPassword(password)
	assert.NoError(t, err2)
	assert.NotEmpty(t, hash2)
	assert.NotEmpty(t, salt2)
	assert.NotEqual(t, hash1, hash2)
	assert.NotEqual(t, salt1, salt2)

	// Verify both hashes work with their respective salts
	assert.True(t, service.verifyPassword(password, hash1, salt1))
	assert.True(t, service.verifyPassword(password, hash2, salt2))
	assert.False(t, service.verifyPassword("wrongpassword", hash1, salt1))
}

func TestUserService_verifyPassword(t *testing.T) {
	mockDynamoDB := &mockDynamoDBClient{}
	mockSES := &mockSESClient{}
	service := NewUserService(mockDynamoDB, mockSES, "test@example.com", "https://example.com")

	password := "TestPassword123!"
	hash, salt, err := service.hashPassword(password)
	assert.NoError(t, err)

	// Test correct password
	assert.True(t, service.verifyPassword(password, hash, salt))

	// Test incorrect password
	assert.False(t, service.verifyPassword("wrongpassword", hash, salt))

	// Test empty password
	assert.False(t, service.verifyPassword("", hash, salt))
}

func TestUserService_generateSecureToken(t *testing.T) {
	mockDynamoDB := &mockDynamoDBClient{}
	mockSES := &mockSESClient{}
	service := NewUserService(mockDynamoDB, mockSES, "test@example.com", "https://example.com")

	token1, err1 := service.generateSecureToken()
	assert.NoError(t, err1)
	assert.NotEmpty(t, token1)
	assert.Equal(t, 64, len(token1)) // 32 bytes = 64 hex characters

	token2, err2 := service.generateSecureToken()
	assert.NoError(t, err2)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2) // Should be different each time
}

func TestUser_ToPublicUser(t *testing.T) {
	now := time.Now()
	user := &User{
		ID:                "user123",
		Username:          "testuser",
		Email:             "test@example.com",
		PasswordHash:      "hashedpassword",
		Salt:              "salt123",
		FullName:          "Test User",
		PhoneNumber:       "1234567890",
		Role:              "user",
		EmailVerified:     true,
		EmailVerifyToken:  "token123",
		EmailVerifyExpiry: now,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastLoginAt:       &now,
		IsActive:          true,
		LoginAttempts:     0,
	}

	publicUser := user.ToPublicUser()

	// Check that public fields are preserved
	assert.Equal(t, user.ID, publicUser.ID)
	assert.Equal(t, user.Username, publicUser.Username)
	assert.Equal(t, user.Email, publicUser.Email)
	assert.Equal(t, user.FullName, publicUser.FullName)
	assert.Equal(t, user.PhoneNumber, publicUser.PhoneNumber)
	assert.Equal(t, user.Role, publicUser.Role)
	assert.Equal(t, user.EmailVerified, publicUser.EmailVerified)
	assert.Equal(t, user.CreatedAt, publicUser.CreatedAt)
	assert.Equal(t, user.UpdatedAt, publicUser.UpdatedAt)
	assert.Equal(t, user.LastLoginAt, publicUser.LastLoginAt)
	assert.Equal(t, user.IsActive, publicUser.IsActive)

	// Check that sensitive fields are not included
	assert.Empty(t, publicUser.PasswordHash)
	assert.Empty(t, publicUser.Salt)
	assert.Empty(t, publicUser.EmailVerifyToken)
	assert.Zero(t, publicUser.EmailVerifyExpiry)
	assert.Zero(t, publicUser.LoginAttempts)
}