# Health Check Implementation - MOBL-3308

## Overview
This implementation adds a comprehensive health check endpoint and monitoring page to the Mobile API, allowing developers and users to monitor API performance and reliability in real-time.

## Implementation Components

### 1. Backend - Go Lambda Function

#### Health Check Endpoint (`/health`)
- **Location**: `submitImage/opendevopslambda/healthcheck.go`
- **Lambda Function**: `healthcheck/main.go`
- **Features**:
  - Real-time status monitoring of AWS services (S3 and DynamoDB)
  - Response time tracking for each service
  - Overall API health status (healthy/degraded)
  - Version information
  - Performance metrics

#### Response Format
```json
{
  "status": "healthy",
  "timestamp": "2023-01-01T00:00:00Z",
  "version": "1.0.0",
  "services": {
    "s3": {
      "status": "healthy",
      "responseTimeMs": 50.5
    },
    "dynamodb": {
      "status": "healthy",
      "responseTimeMs": 30.2
    }
  },
  "performance": {
    "averageResponseTimeMs": 40.35,
    "uptime": "operational"
  }
}
```

#### HTTP Status Codes
- `200 OK`: All services are healthy
- `503 Service Unavailable`: One or more services are degraded/unhealthy

#### Tests
- **Location**: `submitImage/opendevopslambda/healthcheck_test.go`
- **Coverage**: 
  - All services healthy scenario
  - S3 unhealthy scenario
  - DynamoDB unhealthy scenario
  - All services unhealthy scenario

### 2. Frontend - React Health Check Page

#### Health Check Page Component
- **Location**: `src/components/HealthCheckPage.tsx`
- **Features**:
  - Real-time health status display
  - Auto-refresh capability (30-second interval)
  - Manual refresh button
  - Color-coded status indicators (green=healthy, orange=degraded, red=unhealthy)
  - Service-level health breakdown (S3, DynamoDB)
  - Performance metrics visualization
  - Responsive design with modern UI

#### Health Check Service
- **Location**: `src/services/HealthCheckService.ts`
- **Features**:
  - Fetch current health status
  - Periodic health checking
  - Simple health status checking
  - Average response time retrieval
  - Configurable API endpoint

#### Models
- **Location**: `src/models/HealthCheck.ts`
- **Types**: TypeScript interfaces for type-safe health check data handling

#### Tests
- **Location**: `src/services/__tests__/HealthCheckService.test.ts`
- **Coverage**: Service methods, error handling, and API interactions

### 3. API Specification

#### OpenAPI Updates
- **Location**: `api.yaml`
- **Changes**:
  - Added `/health` endpoint definition
  - Added `HealthCheckResponse` schema
  - Added `ServiceStatus` schema
  - Documented response codes and structures

### 4. Infrastructure

#### AWS SAM Template
- **Location**: `template.yml`
- **Changes**:
  - Added `HealthCheckFunction` Lambda resource
  - Configured API Gateway integration for `/health` endpoint
  - Set appropriate IAM permissions (read-only for S3 and DynamoDB)
  - Added CloudFormation outputs for health check API URL

## Deployment

### Prerequisites
- AWS CLI configured
- SAM CLI installed
- Go 1.21+
- Node.js and npm

### Build and Deploy

1. **Build the Lambda functions**:
```bash
make build
```

2. **Deploy to AWS**:
```bash
sam deploy --guided
```

3. **Install frontend dependencies**:
```bash
npm install
```

4. **Run frontend locally**:
```bash
npm start
```

### Configuration

Set the API endpoint in your environment:
```bash
export REACT_APP_API_URL=https://your-api-gateway-url/Prod
```

## Usage

### Accessing the Health Check Endpoint

**API Endpoint**: `GET /health`

```bash
curl https://your-api-gateway-url/Prod/health
```

### Accessing the Health Check Page

Navigate to the health check page in your React application:
```
http://localhost:3000/health
```

## Monitoring and Alerts

The health check endpoint can be integrated with:
- AWS CloudWatch for metrics and alarms
- External monitoring services (Datadog, New Relic, etc.)
- Custom alerting systems
- Load balancer health checks

## Acceptance Criteria Status

✅ **A health check endpoint must be created that returns the current status of the API**
- Implemented at `/health` endpoint
- Returns comprehensive status information including service health and performance metrics

✅ **A health check page must be developed to display performance metrics**
- React component created with real-time monitoring
- Displays all performance metrics and service statuses
- Auto-refresh capability for continuous monitoring

✅ **The endpoint and page should be accessible and provide real-time data on API performance**
- Endpoint is accessible via API Gateway
- Page provides real-time data with 30-second auto-refresh
- Manual refresh available on demand

## Technical Details

### Architecture
- **Backend**: Go-based Lambda function using AWS SDK
- **Frontend**: React with TypeScript
- **API**: RESTful endpoint with JSON responses
- **Infrastructure**: AWS SAM (Serverless Application Model)

### Performance
- Health check completes in < 100ms typically
- Minimal impact on API performance
- Read-only operations on AWS services
- Cached responses via HTTP headers (no-cache for freshness)

### Security
- CORS enabled for cross-origin access
- Read-only IAM permissions for Lambda
- No sensitive data exposed in responses

## Files Created/Modified

### Created Files
- `submitImage/opendevopslambda/healthcheck.go` - Health check handler implementation
- `submitImage/opendevopslambda/healthcheck_test.go` - Health check tests
- `healthcheck/main.go` - Health check Lambda entry point
- `healthcheck/go.mod` - Go module for health check Lambda
- `src/models/HealthCheck.ts` - TypeScript type definitions
- `src/services/HealthCheckService.ts` - Frontend service for health check API
- `src/services/__tests__/HealthCheckService.test.ts` - Service tests
- `src/components/HealthCheckPage.tsx` - Health check UI component
- `src/components/HealthCheckPage.css` - Styling for health check page

### Modified Files
- `api.yaml` - Added health check endpoint specification
- `template.yml` - Added health check Lambda function and API Gateway configuration

## Future Enhancements

Potential improvements for future iterations:
- Historical health data tracking
- Performance trend analysis
- Custom alert thresholds
- Additional service health checks (API Gateway, CloudWatch, etc.)
- Health check metrics dashboard
- Notification system for degraded services
- SLA monitoring and reporting
