package opendevopslambda

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
)

// HealthCheckResponse represents the health check response structure
type HealthCheckResponse struct {
	Status      string                 `json:"status"`
	Timestamp   string                 `json:"timestamp"`
	Version     string                 `json:"version"`
	Services    ServiceHealthStatus    `json:"services"`
	Performance PerformanceMetrics     `json:"performance"`
}

// ServiceHealthStatus contains status of dependent services
type ServiceHealthStatus struct {
	S3       ServiceStatus `json:"s3"`
	DynamoDB ServiceStatus `json:"dynamodb"`
}

// ServiceStatus represents individual service health
type ServiceStatus struct {
	Status       string  `json:"status"`
	ResponseTime float64 `json:"responseTimeMs"`
	Message      string  `json:"message,omitempty"`
}

// PerformanceMetrics contains API performance data
type PerformanceMetrics struct {
	AverageResponseTime float64 `json:"averageResponseTimeMs"`
	Uptime              string  `json:"uptime"`
}

// HealthCheckHandler handles health check requests
func (d *Dependency) HealthCheckHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	startTime := time.Now()
	
	healthResponse := HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   "1.0.0",
	}

	// Check S3 health
	s3Status := d.checkS3Health(ctx)
	
	// Check DynamoDB health
	dynamoStatus := d.checkDynamoDBHealth(ctx)
	
	healthResponse.Services = ServiceHealthStatus{
		S3:       s3Status,
		DynamoDB: dynamoStatus,
	}

	// Determine overall status
	if s3Status.Status != "healthy" || dynamoStatus.Status != "healthy" {
		healthResponse.Status = "degraded"
	}

	// Calculate performance metrics
	totalResponseTime := time.Since(startTime).Milliseconds()
	healthResponse.Performance = PerformanceMetrics{
		AverageResponseTime: float64(totalResponseTime),
		Uptime:              "operational",
	}

	// Marshal response
	responseBody, err := json.Marshal(healthResponse)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Access-Control-Allow-Origin": "*",
			},
			Body: `{"status":"error","message":"Failed to marshal health check response"}`,
		}, err
	}

	statusCode := 200
	if healthResponse.Status == "degraded" {
		statusCode = 503
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Access-Control-Allow-Origin": "*",
			"Cache-Control": "no-cache, no-store, must-revalidate",
		},
		Body: string(responseBody),
	}, nil
}

// checkS3Health checks if S3 service is accessible
func (d *Dependency) checkS3Health(ctx context.Context) ServiceStatus {
	start := time.Now()
	
	// Try to list buckets as a health check
	_, err := d.DepS3.ListBucketsWithContext(ctx, &s3.ListBucketsInput{}, nil)
	
	responseTime := float64(time.Since(start).Milliseconds())
	
	if err != nil {
		return ServiceStatus{
			Status:       "unhealthy",
			ResponseTime: responseTime,
			Message:      fmt.Sprintf("S3 connection failed: %v", err),
		}
	}
	
	return ServiceStatus{
		Status:       "healthy",
		ResponseTime: responseTime,
	}
}

// checkDynamoDBHealth checks if DynamoDB service is accessible
func (d *Dependency) checkDynamoDBHealth(ctx context.Context) ServiceStatus {
	start := time.Now()
	
	// Try to describe the ImageLabels table
	_, err := d.DepDynamoDB.DescribeTableWithContext(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String("ImageLabels"),
	}, nil)
	
	responseTime := float64(time.Since(start).Milliseconds())
	
	if err != nil {
		return ServiceStatus{
			Status:       "unhealthy",
			ResponseTime: responseTime,
			Message:      fmt.Sprintf("DynamoDB connection failed: %v", err),
		}
	}
	
	return ServiceStatus{
		Status:       "healthy",
		ResponseTime: responseTime,
	}
}
