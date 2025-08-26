package repository

import (
	"fmt"
	"time"
	"submit-image/models"
	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

const (
	UsersTableName = "Users"
	UsernameIndexName = "username-index"
	EmailIndexName = "email-index"
)

// UserRepository handles database operations for users
type UserRepository struct {
	dynamoDB dynamodbiface.DynamoDBAPI
}

// NewUserRepository creates a new user repository
func NewUserRepository(dynamoDB dynamodbiface.DynamoDBAPI) *UserRepository {
	return &UserRepository{
		dynamoDB: dynamoDB,
	}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(user *models.User) error {
	// Generate UUID for user ID
	userID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to generate user ID: %w", err)
	}
	
	user.ID = userID.String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.IsActive = true
	user.EmailVerified = false
	
	// Generate email verification token
	verifyToken, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}
	user.EmailVerifyToken = verifyToken.String()
	
	// Convert user to DynamoDB item
	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}
	
	// Create the item in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String(UsersTableName),
		Item:      item,
		// Ensure username and email are unique
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	}
	
	_, err = r.dynamoDB.PutItem(input)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	
	return nil
}

// GetUserByID retrieves a user by their ID
func (r *UserRepository) GetUserByID(userID string) (*models.User, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(UsersTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
	}
	
	result, err := r.dynamoDB.GetItem(input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	
	if result.Item == nil {
		return nil, fmt.Errorf("user not found")
	}
	
	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}
	
	return &user, nil
}

// GetUserByUsername retrieves a user by their username
func (r *UserRepository) GetUserByUsername(username string) (*models.User, error) {
	input := &dynamodb.QueryInput{
		TableName: aws.String(UsersTableName),
		IndexName: aws.String(UsernameIndexName),
		KeyConditionExpression: aws.String("username = :username"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":username": {
				S: aws.String(username),
			},
		},
	}
	
	result, err := r.dynamoDB.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by username: %w", err)
	}
	
	if len(result.Items) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	
	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}
	
	return &user, nil
}

// GetUserByEmail retrieves a user by their email
func (r *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	input := &dynamodb.QueryInput{
		TableName: aws.String(UsersTableName),
		IndexName: aws.String(EmailIndexName),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}
	
	result, err := r.dynamoDB.Query(input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}
	
	if len(result.Items) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	
	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}
	
	return &user, nil
}

// CheckUsernameExists checks if a username already exists
func (r *UserRepository) CheckUsernameExists(username string) (bool, error) {
	_, err := r.GetUserByUsername(username)
	if err != nil {
		if err.Error() == "user not found" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CheckEmailExists checks if an email already exists
func (r *UserRepository) CheckEmailExists(email string) (bool, error) {
	_, err := r.GetUserByEmail(email)
	if err != nil {
		if err.Error() == "user not found" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// UpdateUser updates an existing user
func (r *UserRepository) UpdateUser(user *models.User) error {
	user.UpdatedAt = time.Now()
	
	// Convert user to DynamoDB item
	item, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}
	
	// Update the item in DynamoDB
	input := &dynamodb.PutItemInput{
		TableName: aws.String(UsersTableName),
		Item:      item,
	}
	
	_, err = r.dynamoDB.PutItem(input)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	
	return nil
}

// VerifyEmail marks a user's email as verified using the verification token
func (r *UserRepository) VerifyEmail(token string) error {
	// First, find the user with this verification token
	input := &dynamodb.ScanInput{
		TableName: aws.String(UsersTableName),
		FilterExpression: aws.String("email_verify_token = :token"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
		},
	}
	
	result, err := r.dynamoDB.Scan(input)
	if err != nil {
		return fmt.Errorf("failed to scan for verification token: %w", err)
	}
	
	if len(result.Items) == 0 {
		return fmt.Errorf("invalid verification token")
	}
	
	var user models.User
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return fmt.Errorf("failed to unmarshal user: %w", err)
	}
	
	// Update user to mark email as verified and clear the token
	user.EmailVerified = true
	user.EmailVerifyToken = ""
	user.UpdatedAt = time.Now()
	
	return r.UpdateUser(&user)
}

// UpdateLastLogin updates the user's last login timestamp
func (r *UserRepository) UpdateLastLogin(userID string) error {
	now := time.Now()
	
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(UsersTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
		UpdateExpression: aws.String("SET last_login_at = :lastLogin, updated_at = :updatedAt"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":lastLogin": {
				S: aws.String(now.Format(time.RFC3339)),
			},
			":updatedAt": {
				S: aws.String(now.Format(time.RFC3339)),
			},
		},
	}
	
	_, err := r.dynamoDB.UpdateItem(input)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	
	return nil
}