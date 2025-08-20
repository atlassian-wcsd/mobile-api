package userauth

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

const (
	RateLimitTableName = "RateLimits"
	DefaultRateLimit   = 5  // requests per window
	DefaultWindow      = 60 // seconds
)

// RateLimiter handles rate limiting for API endpoints
type RateLimiter struct {
	dynamoDB dynamodbiface.DynamoDBAPI
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	MaxRequests int           // Maximum requests allowed
	Window      time.Duration // Time window
	Endpoint    string        // Endpoint identifier
}

// RateLimitEntry represents a rate limit entry in the database
type RateLimitEntry struct {
	Key         string    `json:"key"`
	Count       int       `json:"count"`
	WindowStart time.Time `json:"windowStart"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(dynamoDB dynamodbiface.DynamoDBAPI) *RateLimiter {
	return &RateLimiter{
		dynamoDB: dynamoDB,
	}
}

// CheckRateLimit checks if a request should be allowed based on rate limiting
func (rl *RateLimiter) CheckRateLimit(clientIP, endpoint string, config RateLimitConfig) (bool, error) {
	key := fmt.Sprintf("%s:%s", endpoint, clientIP)
	now := time.Now()
	windowStart := now.Truncate(config.Window)

	// Get current rate limit entry
	entry, err := rl.getRateLimitEntry(key)
	if err != nil {
		// If entry doesn't exist, create a new one
		entry = &RateLimitEntry{
			Key:         key,
			Count:       1,
			WindowStart: windowStart,
			ExpiresAt:   windowStart.Add(config.Window),
		}
		
		if err := rl.saveRateLimitEntry(entry); err != nil {
			return false, fmt.Errorf("failed to save rate limit entry: %w", err)
		}
		
		return true, nil
	}

	// Check if we're in a new window
	if windowStart.After(entry.WindowStart) {
		// Reset counter for new window
		entry.Count = 1
		entry.WindowStart = windowStart
		entry.ExpiresAt = windowStart.Add(config.Window)
		
		if err := rl.saveRateLimitEntry(entry); err != nil {
			return false, fmt.Errorf("failed to update rate limit entry: %w", err)
		}
		
		return true, nil
	}

	// Check if limit exceeded
	if entry.Count >= config.MaxRequests {
		return false, nil
	}

	// Increment counter
	entry.Count++
	if err := rl.saveRateLimitEntry(entry); err != nil {
		return false, fmt.Errorf("failed to update rate limit entry: %w", err)
	}

	return true, nil
}

// GetRemainingRequests returns the number of remaining requests in the current window
func (rl *RateLimiter) GetRemainingRequests(clientIP, endpoint string, config RateLimitConfig) (int, time.Duration, error) {
	key := fmt.Sprintf("%s:%s", endpoint, clientIP)
	now := time.Now()
	windowStart := now.Truncate(config.Window)

	entry, err := rl.getRateLimitEntry(key)
	if err != nil {
		// No entry exists, full limit available
		return config.MaxRequests, config.Window, nil
	}

	// Check if we're in a new window
	if windowStart.After(entry.WindowStart) {
		// New window, full limit available
		return config.MaxRequests, config.Window, nil
	}

	remaining := config.MaxRequests - entry.Count
	if remaining < 0 {
		remaining = 0
	}

	// Calculate time until window resets
	resetTime := entry.WindowStart.Add(config.Window).Sub(now)
	if resetTime < 0 {
		resetTime = 0
	}

	return remaining, resetTime, nil
}

// CleanupExpiredEntries removes expired rate limit entries
func (rl *RateLimiter) CleanupExpiredEntries() error {
	now := time.Now()
	
	// Scan for expired entries
	input := &dynamodb.ScanInput{
		TableName:        aws.String(RateLimitTableName),
		FilterExpression: aws.String("expires_at < :now"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":now": {
				N: aws.String(strconv.FormatInt(now.Unix(), 10)),
			},
		},
	}

	result, err := rl.dynamoDB.Scan(input)
	if err != nil {
		return fmt.Errorf("failed to scan for expired entries: %w", err)
	}

	// Delete expired entries
	for _, item := range result.Items {
		if keyAttr, ok := item["key"]; ok && keyAttr.S != nil {
			deleteInput := &dynamodb.DeleteItemInput{
				TableName: aws.String(RateLimitTableName),
				Key: map[string]*dynamodb.AttributeValue{
					"key": {
						S: keyAttr.S,
					},
				},
			}
			
			if _, err := rl.dynamoDB.DeleteItem(deleteInput); err != nil {
				// Log error but continue cleanup
				fmt.Printf("Failed to delete expired rate limit entry %s: %v\n", *keyAttr.S, err)
			}
		}
	}

	return nil
}

// getRateLimitEntry retrieves a rate limit entry from the database
func (rl *RateLimiter) getRateLimitEntry(key string) (*RateLimitEntry, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(RateLimitTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"key": {
				S: aws.String(key),
			},
		},
	}

	result, err := rl.dynamoDB.GetItem(input)
	if err != nil {
		return nil, err
	}

	if len(result.Item) == 0 {
		return nil, fmt.Errorf("rate limit entry not found")
	}

	return rl.itemToRateLimitEntry(result.Item)
}

// saveRateLimitEntry saves a rate limit entry to the database
func (rl *RateLimiter) saveRateLimitEntry(entry *RateLimitEntry) error {
	item := map[string]*dynamodb.AttributeValue{
		"key": {
			S: aws.String(entry.Key),
		},
		"count": {
			N: aws.String(strconv.Itoa(entry.Count)),
		},
		"window_start": {
			S: aws.String(entry.WindowStart.Format(time.RFC3339)),
		},
		"expires_at": {
			N: aws.String(strconv.FormatInt(entry.ExpiresAt.Unix(), 10)),
		},
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(RateLimitTableName),
		Item:      item,
	}

	_, err := rl.dynamoDB.PutItem(input)
	return err
}

// itemToRateLimitEntry converts a DynamoDB item to a RateLimitEntry struct
func (rl *RateLimiter) itemToRateLimitEntry(item map[string]*dynamodb.AttributeValue) (*RateLimitEntry, error) {
	entry := &RateLimitEntry{}

	if v, ok := item["key"]; ok && v.S != nil {
		entry.Key = *v.S
	}

	if v, ok := item["count"]; ok && v.N != nil {
		if count, err := strconv.Atoi(*v.N); err == nil {
			entry.Count = count
		}
	}

	if v, ok := item["window_start"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			entry.WindowStart = t
		}
	}

	if v, ok := item["expires_at"]; ok && v.N != nil {
		if timestamp, err := strconv.ParseInt(*v.N, 10, 64); err == nil {
			entry.ExpiresAt = time.Unix(timestamp, 0)
		}
	}

	return entry, nil
}

// GetDefaultRegistrationRateLimit returns the default rate limit config for registration
func GetDefaultRegistrationRateLimit() RateLimitConfig {
	return RateLimitConfig{
		MaxRequests: 3,                    // 3 registration attempts
		Window:      15 * time.Minute,     // per 15 minutes
		Endpoint:    "register",
	}
}

// GetDefaultLoginRateLimit returns the default rate limit config for login
func GetDefaultLoginRateLimit() RateLimitConfig {
	return RateLimitConfig{
		MaxRequests: 5,                    // 5 login attempts
		Window:      5 * time.Minute,      // per 5 minutes
		Endpoint:    "login",
	}
}

// GetDefaultPasswordResetRateLimit returns the default rate limit config for password reset
func GetDefaultPasswordResetRateLimit() RateLimitConfig {
	return RateLimitConfig{
		MaxRequests: 3,                    // 3 password reset requests
		Window:      1 * time.Hour,        // per hour
		Endpoint:    "password-reset",
	}
}