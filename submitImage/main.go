package main

import (
	"context"
	"strings"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
	"log"
	"os"
	"submit-image/opendevopslambda"

	"github.com/aws/aws-lambda-go/lambda"
)

func init() {
	log.SetOutput(os.Stdout)
}

// Router handles routing between different endpoints
type Router struct {
	imageDependency *opendevopslambda.Dependency
	appleAuthHandler *opendevopslambda.AppleAuthHandler
	userAuthHandler *opendevopslambda.UserAuthHandler
}

// NewRouter creates a new router with all handlers
func NewRouter() (*Router, error) {
	sess := session.Must(session.NewSession())
	
	imageDep := &opendevopslambda.Dependency{
		DepS3: s3.New(sess),
		DepDynamoDB: dynamodb.New(sess),
	}

	appleHandler, err := opendevopslambda.NewAppleAuthHandler()
	if err != nil {
		log.Printf("Warning: Failed to initialize Apple Auth Handler: %v", err)
		// Continue without Apple auth if configuration is missing
	}

	// Initialize user auth handler
	dynamoDBClient := dynamodb.New(sess)
	sesClient := ses.New(sess)
	fromEmail := os.Getenv("FROM_EMAIL")
	baseURL := os.Getenv("BASE_URL")
	
	if fromEmail == "" {
		fromEmail = "noreply@yourapp.com" // Default fallback
	}
	if baseURL == "" {
		baseURL = "https://yourapp.com" // Default fallback
	}
	
	userAuthHandler := opendevopslambda.NewUserAuthHandler(dynamoDBClient, sesClient, fromEmail, baseURL)

	return &Router{
		imageDependency: imageDep,
		appleAuthHandler: appleHandler,
		userAuthHandler: userAuthHandler,
	}, nil
}

// Handler routes requests to appropriate handlers based on path
func (r *Router) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	path := request.Path
	method := request.HTTPMethod

	log.Printf("Handling request: %s %s", method, path)

	// User Authentication routes
	if r.userAuthHandler != nil {
		switch {
		case path == "/api/register" && method == "POST":
			return r.userAuthHandler.HandleRegister(ctx, request)
		case path == "/api/login" && method == "POST":
			return r.userAuthHandler.HandleLogin(ctx, request)
		case path == "/api/verify-email" && method == "POST":
			return r.userAuthHandler.HandleVerifyEmail(ctx, request)
		case path == "/api/password-reset" && method == "POST":
			return r.userAuthHandler.HandlePasswordReset(ctx, request)
		case path == "/api/password-reset-confirm" && method == "POST":
			return r.userAuthHandler.HandlePasswordResetConfirm(ctx, request)
		case strings.HasPrefix(path, "/api/") && method == "OPTIONS":
			return r.userAuthHandler.HandleOptions(ctx, request)
		}
	}

	// Apple Authentication routes
	if r.appleAuthHandler != nil {
		switch {
		case path == "/auth/apple/verify" && method == "POST":
			return r.appleAuthHandler.HandleVerifyToken(ctx, request)
		case path == "/auth/apple/refresh" && method == "POST":
			return r.appleAuthHandler.HandleRefreshToken(ctx, request)
		case path == "/auth/apple/signout" && method == "POST":
			return r.appleAuthHandler.HandleSignOut(ctx, request)
		case path == "/auth/apple/profile" && method == "GET":
			return r.appleAuthHandler.HandleGetProfile(ctx, request)
		case strings.HasPrefix(path, "/auth/apple/") && method == "OPTIONS":
			return r.appleAuthHandler.HandleOptions(ctx, request)
		}
	}

	// Default to image submission handler for backward compatibility
	// This handles the original image submission functionality
	return r.imageDependency.Handler(ctx, request)
}

func main() {
	router, err := NewRouter()
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

	lambda.Start(router.Handler)
}
