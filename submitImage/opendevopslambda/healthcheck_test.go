package opendevopslambda

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/assert"
)

// Mock S3 client
type mockS3Client struct {
	s3iface.S3API
	shouldFail bool
}

func (m *mockS3Client) ListBucketsWithContext(ctx aws.Context, input *s3.ListBucketsInput, opts ...request.Option) (*s3.ListBucketsOutput, error) {
	if m.shouldFail {
		return nil, errors.New("S3 connection error")
	}
	return &s3.ListBucketsOutput{}, nil
}

// Mock DynamoDB client
type mockDynamoDBClient struct {
	dynamodbiface.DynamoDBAPI
	shouldFail bool
}

func (m *mockDynamoDBClient) DescribeTableWithContext(ctx aws.Context, input *dynamodb.DescribeTableInput, opts ...request.Option) (*dynamodb.DescribeTableOutput, error) {
	if m.shouldFail {
		return nil, errors.New("DynamoDB connection error")
	}
	return &dynamodb.DescribeTableOutput{}, nil
}

func TestHealthCheckHandler_AllServicesHealthy(t *testing.T) {
	dep := &Dependency{
		DepS3:       &mockS3Client{shouldFail: false},
		DepDynamoDB: &mockDynamoDBClient{shouldFail: false},
	}

	ctx := context.Background()
	request := events.APIGatewayProxyRequest{}

	response, err := dep.HealthCheckHandler(ctx, request)

	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "application/json", response.Headers["Content-Type"])
	assert.Equal(t, "*", response.Headers["Access-Control-Allow-Origin"])

	var healthResponse HealthCheckResponse
	err = json.Unmarshal([]byte(response.Body), &healthResponse)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", healthResponse.Status)
	assert.Equal(t, "healthy", healthResponse.Services.S3.Status)
	assert.Equal(t, "healthy", healthResponse.Services.DynamoDB.Status)
	assert.NotEmpty(t, healthResponse.Timestamp)
	assert.Equal(t, "1.0.0", healthResponse.Version)
}

func TestHealthCheckHandler_S3Unhealthy(t *testing.T) {
	dep := &Dependency{
		DepS3:       &mockS3Client{shouldFail: true},
		DepDynamoDB: &mockDynamoDBClient{shouldFail: false},
	}

	ctx := context.Background()
	request := events.APIGatewayProxyRequest{}

	response, err := dep.HealthCheckHandler(ctx, request)

	assert.NoError(t, err)
	assert.Equal(t, 503, response.StatusCode)

	var healthResponse HealthCheckResponse
	err = json.Unmarshal([]byte(response.Body), &healthResponse)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", healthResponse.Status)
	assert.Equal(t, "unhealthy", healthResponse.Services.S3.Status)
	assert.Equal(t, "healthy", healthResponse.Services.DynamoDB.Status)
}

func TestHealthCheckHandler_DynamoDBUnhealthy(t *testing.T) {
	dep := &Dependency{
		DepS3:       &mockS3Client{shouldFail: false},
		DepDynamoDB: &mockDynamoDBClient{shouldFail: true},
	}

	ctx := context.Background()
	request := events.APIGatewayProxyRequest{}

	response, err := dep.HealthCheckHandler(ctx, request)

	assert.NoError(t, err)
	assert.Equal(t, 503, response.StatusCode)

	var healthResponse HealthCheckResponse
	err = json.Unmarshal([]byte(response.Body), &healthResponse)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", healthResponse.Status)
	assert.Equal(t, "healthy", healthResponse.Services.S3.Status)
	assert.Equal(t, "unhealthy", healthResponse.Services.DynamoDB.Status)
}

func TestHealthCheckHandler_AllServicesUnhealthy(t *testing.T) {
	dep := &Dependency{
		DepS3:       &mockS3Client{shouldFail: true},
		DepDynamoDB: &mockDynamoDBClient{shouldFail: true},
	}

	ctx := context.Background()
	request := events.APIGatewayProxyRequest{}

	response, err := dep.HealthCheckHandler(ctx, request)

	assert.NoError(t, err)
	assert.Equal(t, 503, response.StatusCode)

	var healthResponse HealthCheckResponse
	err = json.Unmarshal([]byte(response.Body), &healthResponse)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", healthResponse.Status)
	assert.Equal(t, "unhealthy", healthResponse.Services.S3.Status)
	assert.Equal(t, "unhealthy", healthResponse.Services.DynamoDB.Status)
}
