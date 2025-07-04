package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"submit-image/opendevopslambda"
)

// Enhanced router with middleware support and better error handling
type Router struct {
	imageDependency  *opendevopslambda.Dependency
	appleAuthHandler *opendevopslambda.AppleAuthHandler
	middlewares      []Middleware
}

// Middleware interface for request/response processing
type Middleware interface {
	Process(ctx context.Context, request events.APIGatewayProxyRequest, next HandlerFunc) (events.APIGatewayProxyResponse, error)
}

// HandlerFunc represents a handler function
type HandlerFunc func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)

// Route represents a single route
type Route struct {
	Path    string
	Method  string
	Handler HandlerFunc
}

// RouterConfig holds router configuration
type RouterConfig struct {
	EnableCORS      bool
	EnableLogging   bool
	EnableMetrics   bool
	RequestTimeout  time.Duration
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// NewRouter creates a new router with enhanced configuration
func NewRouter(config RouterConfig) (*Router, error) {
	sess := session.Must(session.NewSession())
	
	imageDep := &opendevopslambda.Dependency{
		DepS3:       s3.New(sess),
		DepDynamoDB: dynamodb.New(sess),
	}

	// Initialize Apple Auth Handler with better error handling
	var appleHandler *opendevopslambda.AppleAuthHandler
	var err error
	
	if hasAppleConfig() {
		appleHandler, err = opendevopslambda.NewAppleAuthHandler()
		if err != nil {
			log.Printf("Warning: Failed to initialize Apple Auth Handler: %v", err)
			// Continue without Apple auth but log the issue
		} else {
			log.Println("Apple Auth Handler initialized successfully")
		}
	} else {
		log.Println("Apple Auth configuration not found, skipping Apple Auth Handler")
	}

	router := &Router{
		imageDependency:  imageDep,
		appleAuthHandler: appleHandler,
		middlewares:      []Middleware{},
	}

	// Add default middlewares based on config
	if config.EnableLogging {
		router.Use(&LoggingMiddleware{})
	}
	
	if config.EnableCORS {
		router.Use(&CORSMiddleware{})
	}
	
	if config.EnableMetrics {
		router.Use(&MetricsMiddleware{})
	}

	if config.RequestTimeout > 0 {
		router.Use(&TimeoutMiddleware{Timeout: config.RequestTimeout})
	}

	return router, nil
}

// Use adds a middleware to the router
func (r *Router) Use(middleware Middleware) {
	r.middlewares = append(r.middlewares, middleware)
}

// Handler routes requests with middleware support and better error handling
func (r *Router) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Create the final handler
	finalHandler := r.routeRequest
	
	// Apply middlewares in reverse order
	for i := len(r.middlewares) - 1; i >= 0; i-- {
		middleware := r.middlewares[i]
		currentHandler := finalHandler
		finalHandler = func(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
			return middleware.Process(ctx, req, currentHandler)
		}
	}
	
	return finalHandler(ctx, request)
}

// routeRequest handles the actual routing logic
func (r *Router) routeRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	path := request.Path
	method := request.HTTPMethod

	// Define routes
	routes := r.getRoutes()
	
	// Find matching route
	for _, route := range routes {
		if r.matchRoute(route, path, method) {
			return route.Handler(ctx, request)
		}
	}

	// No route found, return 404
	return r.notFoundHandler(ctx, request)
}

// getRoutes returns all available routes
func (r *Router) getRoutes() []Route {
	routes := []Route{
		// Health check endpoint
		{Path: "/health", Method: "GET", Handler: r.healthCheckHandler},
	}

	// Add Apple Auth routes if handler is available
	if r.appleAuthHandler != nil {
		appleRoutes := []Route{
			{Path: "/auth/apple/verify", Method: "POST", Handler: r.appleAuthHandler.HandleVerifyToken},
			{Path: "/auth/apple/refresh", Method: "POST", Handler: r.appleAuthHandler.HandleRefreshToken},
			{Path: "/auth/apple/signout", Method: "POST", Handler: r.appleAuthHandler.HandleSignOut},
			{Path: "/auth/apple/profile", Method: "GET", Handler: r.appleAuthHandler.HandleGetProfile},
		}
		routes = append(routes, appleRoutes...)
		
		// Add OPTIONS handlers for CORS
		for _, route := range appleRoutes {
			routes = append(routes, Route{
				Path:    route.Path,
				Method:  "OPTIONS",
				Handler: r.appleAuthHandler.HandleOptions,
			})
		}
	}

	return routes
}

// matchRoute checks if a route matches the request
func (r *Router) matchRoute(route Route, path, method string) bool {
	// Exact path match for now (could be enhanced with path parameters)
	return route.Path == path && route.Method == method
}

// healthCheckHandler provides a health check endpoint
func (r *Router) healthCheckHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"services": map[string]string{
			"image_service": "available",
		},
	}

	// Check Apple Auth service if available
	if r.appleAuthHandler != nil {
		health["services"].(map[string]string)["apple_auth"] = "available"
	} else {
		health["services"].(map[string]string)["apple_auth"] = "unavailable"
	}

	body, _ := json.Marshal(health)
	
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}, nil
}

// notFoundHandler handles 404 responses
func (r *Router) notFoundHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	errorResponse := map[string]interface{}{
		"error":   "Not Found",
		"message": fmt.Sprintf("Route %s %s not found", request.HTTPMethod, request.Path),
		"path":    request.Path,
		"method":  request.HTTPMethod,
	}

	body, _ := json.Marshal(errorResponse)
	
	return events.APIGatewayProxyResponse{
		StatusCode: 404,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}, nil
}

// hasAppleConfig checks if Apple configuration is available
func hasAppleConfig() bool {
	required := []string{"APPLE_CLIENT_ID", "APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			return false
		}
	}
	return true
}

// Middleware implementations

// LoggingMiddleware logs requests and responses
type LoggingMiddleware struct{}

func (m *LoggingMiddleware) Process(ctx context.Context, request events.APIGatewayProxyRequest, next HandlerFunc) (events.APIGatewayProxyResponse, error) {
	start := time.Now()
	
	log.Printf("Request: %s %s", request.HTTPMethod, request.Path)
	
	response, err := next(ctx, request)
	
	duration := time.Since(start)
	log.Printf("Response: %d in %v", response.StatusCode, duration)
	
	return response, err
}

// CORSMiddleware handles CORS headers
type CORSMiddleware struct{}

func (m *CORSMiddleware) Process(ctx context.Context, request events.APIGatewayProxyRequest, next HandlerFunc) (events.APIGatewayProxyResponse, error) {
	response, err := next(ctx, request)
	
	// Add CORS headers
	if response.Headers == nil {
		response.Headers = make(map[string]string)
	}
	
	response.Headers["Access-Control-Allow-Origin"] = "*"
	response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
	response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
	response.Headers["Access-Control-Max-Age"] = "86400"
	
	return response, err
}

// MetricsMiddleware collects metrics
type MetricsMiddleware struct{}

func (m *MetricsMiddleware) Process(ctx context.Context, request events.APIGatewayProxyRequest, next HandlerFunc) (events.APIGatewayProxyResponse, error) {
	start := time.Now()
	
	response, err := next(ctx, request)
	
	duration := time.Since(start)
	
	// Log metrics (in production, you'd send to CloudWatch)
	log.Printf("METRIC: path=%s method=%s status=%d duration=%v", 
		request.Path, request.HTTPMethod, response.StatusCode, duration)
	
	return response, err
}

// TimeoutMiddleware adds request timeout
type TimeoutMiddleware struct {
	Timeout time.Duration
}

func (m *TimeoutMiddleware) Process(ctx context.Context, request events.APIGatewayProxyRequest, next HandlerFunc) (events.APIGatewayProxyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()
	
	type result struct {
		response events.APIGatewayProxyResponse
		err      error
	}
	
	resultChan := make(chan result, 1)
	
	go func() {
		response, err := next(ctx, request)
		resultChan <- result{response, err}
	}()
	
	select {
	case res := <-resultChan:
		return res.response, res.err
	case <-ctx.Done():
		return events.APIGatewayProxyResponse{
			StatusCode: 408,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: `{"error": "Request Timeout", "message": "Request took too long to process"}`,
		}, nil
	}
}

func main() {
	config := RouterConfig{
		EnableCORS:     true,
		EnableLogging:  true,
		EnableMetrics:  true,
		RequestTimeout: 30 * time.Second,
	}

	router, err := NewRouter(config)
	if err != nil {
		log.Fatalf("Failed to create router: %v", err)
	}

	log.Println("Lambda function starting...")
	lambda.Start(router.Handler)
}