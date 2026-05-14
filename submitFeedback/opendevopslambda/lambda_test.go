package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

type mockedPutItem struct {
	dynamodbiface.DynamoDBAPI
	Response dynamodb.PutItemOutput
}

func (d mockedPutItem) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	return &d.Response, nil
}

func createTestContext() context.Context {
	ctx := context.Background()
	lc := new(lambdacontext.LambdaContext)
	lc.InvokedFunctionArn = "arn:aws:lambda:us-east-1:123456789000:function:submitFeedback"
	return lambdacontext.NewContext(ctx, lc)
}

func createDependency() Dependency {
	mpi := mockedPutItem{
		Response: dynamodb.PutItemOutput{},
	}
	return Dependency{
		DepDynamoDB: mpi,
	}
}

func TestHandler(t *testing.T) {
	t.Run("Successful Feedback Submission", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:       "user-123",
			Category:     "general",
			Rating:       5,
			Message:      "Great app! Love the signature feature.",
			ContactEmail: "user@example.com",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 201 {
			t.Fatal(fmt.Sprintf("Expected status 201, got %d. Body: %s", resp.StatusCode, resp.Body))
		}

		var respBody FeedbackResponse
		if err := json.Unmarshal([]byte(resp.Body), &respBody); err != nil {
			t.Fatal(fmt.Sprintf("Failed to parse response body: %s", err.Error()))
		}
		if respBody.Status != "submitted" {
			t.Fatal(fmt.Sprintf("Expected status 'submitted', got '%s'", respBody.Status))
		}
		if respBody.FeedbackID == "" {
			t.Fatal("Expected non-empty feedbackId")
		}
	})

	t.Run("Missing Required Fields", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:   "",
			Category: "general",
			Rating:   5,
			Message:  "Test",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprintf("Expected status 400, got %d", resp.StatusCode))
		}
	})

	t.Run("Invalid Rating", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:   "user-123",
			Category: "bug",
			Rating:   6,
			Message:  "Rating out of range",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprintf("Expected status 400 for invalid rating, got %d", resp.StatusCode))
		}
	})

	t.Run("Invalid Category", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:   "user-123",
			Category: "invalid_category",
			Rating:   3,
			Message:  "Testing invalid category",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprintf("Expected status 400 for invalid category, got %d", resp.StatusCode))
		}
	})

	t.Run("Invalid Email Format", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:       "user-123",
			Category:     "general",
			Rating:       4,
			Message:      "Testing invalid email",
			ContactEmail: "not-an-email",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprintf("Expected status 400 for invalid email, got %d", resp.StatusCode))
		}
	})

	t.Run("Invalid JSON Body", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       "not valid json",
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 400 {
			t.Fatal(fmt.Sprintf("Expected status 400 for invalid JSON, got %d", resp.StatusCode))
		}
	})

	t.Run("CORS Preflight Request", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "OPTIONS",
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 200 {
			t.Fatal(fmt.Sprintf("Expected status 200 for OPTIONS, got %d", resp.StatusCode))
		}
		if resp.Headers["Access-Control-Allow-Origin"] != "*" {
			t.Fatal("Expected CORS header Access-Control-Allow-Origin to be '*'")
		}
	})

	t.Run("Submission Without Optional Email", func(t *testing.T) {
		d := createDependency()
		ctx := createTestContext()

		body, _ := json.Marshal(FeedbackRequest{
			UserID:   "user-456",
			Category: "feature_request",
			Rating:   4,
			Message:  "Would love to see dark mode support!",
		})

		request := events.APIGatewayProxyRequest{
			HTTPMethod: "POST",
			Body:       string(body),
		}

		resp, err := d.Handler(ctx, request)
		if err != nil {
			t.Fatal(fmt.Sprintf("Handler failed with error: %s", err.Error()))
		}
		if resp.StatusCode != 201 {
			t.Fatal(fmt.Sprintf("Expected status 201, got %d", resp.StatusCode))
		}
	})
}

func TestValidateFeedbackRequest(t *testing.T) {
	t.Run("Valid Request", func(t *testing.T) {
		req := FeedbackRequest{
			UserID:   "user-123",
			Category: "bug",
			Rating:   3,
			Message:  "Found a bug in the signature feature",
		}
		if err := validateFeedbackRequest(req); err != nil {
			t.Fatal(fmt.Sprintf("Expected valid request, got error: %s", err.Error()))
		}
	})

	t.Run("Empty Message", func(t *testing.T) {
		req := FeedbackRequest{
			UserID:   "user-123",
			Category: "general",
			Rating:   5,
			Message:  "   ",
		}
		if err := validateFeedbackRequest(req); err == nil {
			t.Fatal("Expected error for empty message")
		}
	})

	t.Run("Rating Zero", func(t *testing.T) {
		req := FeedbackRequest{
			UserID:   "user-123",
			Category: "general",
			Rating:   0,
			Message:  "Test",
		}
		if err := validateFeedbackRequest(req); err == nil {
			t.Fatal("Expected error for zero rating")
		}
	})
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"user@example.com", true},
		{"name@domain.co.uk", true},
		{"test@test.io", true},
		{"invalid", false},
		{"@domain.com", false},
		{"user@", false},
		{"user@domain", false},
		{"user @example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := isValidEmail(tt.email)
			if result != tt.expected {
				t.Fatal(fmt.Sprintf("isValidEmail(%s) = %v, expected %v", tt.email, result, tt.expected))
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "Hello World"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"},
		{"Tom & Jerry", "Tom &amp; Jerry"},
		{`He said "hello"`, "He said &quot;hello&quot;"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeInput(tt.input)
			if result != tt.expected {
				t.Fatal(fmt.Sprintf("sanitizeInput(%s) = %s, expected %s", tt.input, result, tt.expected))
			}
		})
	}
}
