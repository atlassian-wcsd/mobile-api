package main

import (
	"context"
	"strings"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
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
	feedbackHandler *opendevopslambda.FeedbackHandler
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

	feedbackHandler := opendevopslambda.NewFeedbackHandler(dynamodb.New(sess))

	return &Router{
		imageDependency: imageDep,
		appleAuthHandler: appleHandler,
		feedbackHandler: feedbackHandler,
	}, nil
}

// Handler routes requests to appropriate handlers based on path
func (r *Router) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	path := request.Path
	method := request.HTTPMethod

	log.Printf("Handling request: %s %s", method, path)

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

	// Feedback routes
	if strings.HasPrefix(path, "/feedback") {
		return r.feedbackHandler.HandleFeedbackRequest(ctx, request)
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
