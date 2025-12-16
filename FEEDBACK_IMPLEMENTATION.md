# User Feedback and Metrics Collection - Implementation Guide

This document provides a comprehensive guide for the user feedback and metrics collection feature implementation for MOBL-3244.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Database Schema](#database-schema)
4. [Backend Implementation](#backend-implementation)
5. [Frontend Implementation](#frontend-implementation)
6. [API Documentation](#api-documentation)
7. [Testing](#testing)
8. [Deployment](#deployment)
9. [Security Considerations](#security-considerations)
10. [Monitoring and Analytics](#monitoring-and-analytics)

## Overview

This implementation provides a complete system for collecting user feedback and tracking metrics from end users, storing the data in DynamoDB, and providing APIs for submission and retrieval.

### Features

- ✅ User feedback submission (bugs, features, improvements, general)
- ✅ Star rating system (1-5 stars)
- ✅ Category-based organization
- ✅ User metrics and event tracking
- ✅ Session tracking
- ✅ Device and browser detection
- ✅ Performance timing metrics
- ✅ Error tracking
- ✅ User feedback history retrieval
- ✅ Responsive UI components
- ✅ Accessibility compliant (WCAG 2.1)

## Architecture

### System Components

```
┌─────────────┐      ┌──────────────┐      ┌──────────────┐
│   Frontend  │─────▶│  API Gateway │─────▶│    Lambda    │
│  (React)    │      │              │      │   Function   │
└─────────────┘      └──────────────┘      └──────┬───────┘
                                                   │
                                                   ▼
                                            ┌──────────────┐
                                            │  DynamoDB    │
                                            │   Tables     │
                                            └──────────────┘
```

### Data Flow

1. **Feedback Submission**: User → FeedbackForm → FeedbackService → API → Lambda → DynamoDB
2. **Metrics Tracking**: User Action → MetricsTracker → FeedbackService → API → Lambda → DynamoDB
3. **Feedback Retrieval**: User → API → Lambda → DynamoDB → User

## Database Schema

### DynamoDB Tables

#### 1. UserFeedback Table

```yaml
Table Name: UserFeedback
Primary Key: Id (String)
Global Secondary Indexes:
  - UserIdIndex:
      Partition Key: UserId (String)
      Sort Key: CreatedAt (String)
  - StatusIndex:
      Partition Key: Status (String)
      Sort Key: CreatedAt (String)

Attributes:
  - Id: Unique feedback identifier (UUID)
  - UserId: User who submitted feedback
  - FeedbackType: bug | feature | improvement | general
  - Rating: Optional 1-5 star rating
  - Title: Feedback title (3-200 chars)
  - Message: Detailed message (10-5000 chars)
  - Category: Feature category
  - PageContext: Page where submitted
  - UserAgent: Browser user agent
  - DeviceInfo: Device and browser details
  - CreatedAt: Submission timestamp
  - Status: pending | reviewed | resolved | closed
  - Email: Optional contact email
  - AllowContact: Boolean
  - AttachmentIds: Array of attachment IDs
  - AdminNotes: Internal notes
  - UpdatedAt: Last update timestamp
```

#### 2. UserMetrics Table

```yaml
Table Name: UserMetrics
Primary Key: Id (String)
Global Secondary Indexes:
  - UserIdIndex:
      Partition Key: UserId (String)
      Sort Key: Timestamp (String)
  - EventTypeIndex:
      Partition Key: EventType (String)
      Sort Key: Timestamp (String)
  - SessionIndex:
      Partition Key: SessionId (String)
      Sort Key: Timestamp (String)

Attributes:
  - Id: Unique metric identifier (UUID)
  - UserId: User associated with metric
  - EventType: Type of event (action, navigation, timing, error)
  - EventName: Specific event name
  - Properties: JSON object with event data
  - SessionId: Session identifier
  - Page: Page/screen where event occurred
  - Duration: Duration in ms (for timing events)
  - Timestamp: Event timestamp
  - Context: Device and browser context
  - Geo: Geographic information (optional)
```

### DynamoDB Setup Commands

```bash
# Create UserFeedback table
aws dynamodb create-table \
  --table-name UserFeedback \
  --attribute-definitions \
    AttributeName=Id,AttributeType=S \
    AttributeName=UserId,AttributeType=S \
    AttributeName=Status,AttributeType=S \
    AttributeName=CreatedAt,AttributeType=S \
  --key-schema AttributeName=Id,KeyType=HASH \
  --global-secondary-indexes \
    "[{
      \"IndexName\": \"UserIdIndex\",
      \"KeySchema\": [{\"AttributeName\":\"UserId\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"CreatedAt\",\"KeyType\":\"RANGE\"}],
      \"Projection\": {\"ProjectionType\":\"ALL\"},
      \"ProvisionedThroughput\": {\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
    },{
      \"IndexName\": \"StatusIndex\",
      \"KeySchema\": [{\"AttributeName\":\"Status\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"CreatedAt\",\"KeyType\":\"RANGE\"}],
      \"Projection\": {\"ProjectionType\":\"ALL\"},
      \"ProvisionedThroughput\": {\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
    }]" \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

# Create UserMetrics table
aws dynamodb create-table \
  --table-name UserMetrics \
  --attribute-definitions \
    AttributeName=Id,AttributeType=S \
    AttributeName=UserId,AttributeType=S \
    AttributeName=EventType,AttributeType=S \
    AttributeName=SessionId,AttributeType=S \
    AttributeName=Timestamp,AttributeType=S \
  --key-schema AttributeName=Id,KeyType=HASH \
  --global-secondary-indexes \
    "[{
      \"IndexName\": \"UserIdIndex\",
      \"KeySchema\": [{\"AttributeName\":\"UserId\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"Timestamp\",\"KeyType\":\"RANGE\"}],
      \"Projection\": {\"ProjectionType\":\"ALL\"},
      \"ProvisionedThroughput\": {\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
    },{
      \"IndexName\": \"EventTypeIndex\",
      \"KeySchema\": [{\"AttributeName\":\"EventType\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"Timestamp\",\"KeyType\":\"RANGE\"}],
      \"Projection\": {\"ProjectionType\":\"ALL\"},
      \"ProvisionedThroughput\": {\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
    },{
      \"IndexName\": \"SessionIndex\",
      \"KeySchema\": [{\"AttributeName\":\"SessionId\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"Timestamp\",\"KeyType\":\"RANGE\"}],
      \"Projection\": {\"ProjectionType\":\"ALL\"},
      \"ProvisionedThroughput\": {\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
    }]" \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

## Backend Implementation

### Key Files

1. **Models** (`submitImage/models/feedback.go`)
   - Data structures for feedback and metrics
   - Request/response types
   - Validation rules

2. **Handler** (`submitImage/opendevopslambda/feedback_handler.go`)
   - API endpoint handlers
   - Business logic
   - DynamoDB operations

3. **Router** (`submitImage/main.go`)
   - Route registration
   - Request routing

4. **JWT Utils** (`submitImage/opendevopslambda/jwt_utils.go`)
   - Token generation and verification
   - User authentication

### API Endpoints

#### 1. POST /feedback
Submit user feedback

**Request:**
```json
{
  "feedbackType": "bug",
  "rating": 4,
  "title": "Button not responding",
  "message": "The submit button doesn't work on mobile devices when...",
  "category": "ui",
  "pageContext": "/signature",
  "email": "user@example.com",
  "allowContact": true
}
```

**Response:**
```json
{
  "success": true,
  "feedbackId": "uuid-123",
  "message": "Feedback submitted successfully. Thank you for your input!"
}
```

#### 2. GET /feedback
Retrieve user's feedback history

**Response:**
```json
{
  "success": true,
  "feedback": [
    {
      "id": "uuid-123",
      "userId": "user-456",
      "feedbackType": "bug",
      "rating": 4,
      "title": "Button not responding",
      "message": "The submit button doesn't...",
      "category": "ui",
      "status": "pending",
      "createdAt": "2024-01-15T10:30:00Z"
    }
  ],
  "count": 1
}
```

#### 3. POST /metrics/track
Track user event/metric

**Request:**
```json
{
  "eventType": "action",
  "eventName": "button_click",
  "properties": {
    "buttonId": "submit",
    "formType": "feedback"
  },
  "sessionId": "session-789",
  "page": "/feedback",
  "duration": 150
}
```

**Response:**
```json
{
  "success": true,
  "metricId": "uuid-metric-123",
  "message": "Metric tracked successfully"
}
```

## Frontend Implementation

### Key Components

#### 1. FeedbackForm (`src/components/FeedbackForm.tsx`)
Complete feedback submission form with:
- Type selection (bug, feature, improvement, general)
- Star rating (optional)
- Title and message fields
- Category selection
- Email and contact preference
- Real-time validation
- Character count
- Success/error feedback

**Usage:**
```tsx
import { FeedbackForm } from './components/FeedbackForm';

<FeedbackForm
  onSuccess={() => console.log('Feedback submitted!')}
  onCancel={() => console.log('Cancelled')}
  defaultCategory="signature"
  defaultType="bug"
/>
```

#### 2. FeedbackButton (`src/components/FeedbackButton.tsx`)
Floating feedback button with modal:
- Customizable position
- Modal overlay
- Responsive design

**Usage:**
```tsx
import { FeedbackButton } from './components/FeedbackButton';

<FeedbackButton
  position="bottom-right"
  buttonText="💬 Feedback"
/>
```

#### 3. MetricsTracker (`src/components/MetricsTracker.tsx`)
Automatic metrics tracking wrapper:
- Page views
- Navigation timing
- Error tracking
- Visibility changes
- Session tracking

**Usage:**
```tsx
import { MetricsTracker } from './components/MetricsTracker';

<MetricsTracker>
  <App />
</MetricsTracker>
```

#### 4. FeedbackService (`src/services/FeedbackService.ts`)
Service layer for API communication:
- Feedback submission
- Metrics tracking
- Device detection
- Session management

**Usage:**
```tsx
import { feedbackService } from './services/FeedbackService';

// Submit feedback
await feedbackService.submitFeedback({
  feedbackType: 'bug',
  title: 'Issue found',
  message: 'Description...',
  category: 'general',
  allowContact: false
});

// Track event
await feedbackService.trackEvent('action', 'button_click', {
  buttonId: 'submit'
});

// Track page view
await feedbackService.trackPageView('/home');

// Track error
await feedbackService.trackError(error, { context: 'payment' });
```

## API Documentation

Full API documentation is available in `api.yaml` (OpenAPI 3.0 format).

View documentation:
```bash
# Using Swagger UI
npx swagger-ui-dist api.yaml

# Using Redoc
npx redoc-cli serve api.yaml
```

## Testing

### Backend Tests

Run Go tests:
```bash
cd submitImage
go test ./... -v -cover
```

Test files:
- `submitImage/opendevopslambda/feedback_handler_test.go`

### Frontend Tests

Run Jest tests:
```bash
npm test
```

Test files:
- `src/services/__tests__/FeedbackService.test.ts`
- `src/components/__tests__/FeedbackForm.test.tsx`

### Test Coverage

Ensure minimum coverage:
- Backend: 80%
- Frontend: 75%

## Deployment

### 1. Build Backend

```bash
cd submitImage
GOOS=linux GOARCH=amd64 go build -o bootstrap main.go
```

### 2. Deploy with SAM

```bash
sam build
sam deploy --guided
```

### 3. Deploy Frontend

```bash
npm run build
# Deploy build/ directory to your hosting service
```

### 4. Environment Variables

Set these in AWS Lambda:
```bash
JWT_SECRET=your-secret-key
APPLE_CLIENT_ID=your-apple-client-id
APPLE_TEAM_ID=your-apple-team-id
APPLE_KEY_ID=your-apple-key-id
APPLE_PRIVATE_KEY=your-apple-private-key
```

## Security Considerations

### Authentication & Authorization

1. **JWT Token Validation**
   - All feedback and metrics endpoints require valid JWT tokens
   - Tokens must be included in Authorization header: `Bearer <token>`
   - Token expiration is enforced

2. **Input Validation**
   - Title: 3-200 characters
   - Message: 10-5000 characters
   - Rating: 1-5 stars
   - Email: Valid email format
   - Feedback type: Enum validation

3. **Rate Limiting**
   - Implement rate limiting at API Gateway level
   - Recommended: 100 requests per minute per user

4. **Data Protection**
   - Email addresses are optional
   - PII data is handled according to GDPR/CCPA
   - User can opt-in/out of contact

5. **CORS Configuration**
   - Configured for specific origins in production
   - Currently allows `*` for development

### Encryption

- Data at rest: DynamoDB encryption enabled
- Data in transit: HTTPS/TLS 1.2+
- JWT tokens: HS256 signing algorithm

## Monitoring and Analytics

### CloudWatch Metrics

Monitor:
- API request count
- Error rates
- Response times
- DynamoDB read/write capacity
- Lambda invocations and errors

### Custom Metrics

Track:
- Feedback submission rate
- Average rating
- Feedback by type/category
- Most common issues
- User engagement metrics

### Dashboards

Create dashboards for:
1. **Feedback Overview**
   - Total feedback count
   - Feedback by type
   - Average rating
   - Status distribution

2. **User Engagement**
   - Active users
   - Session duration
   - Page views
   - Event frequency

3. **Performance**
   - API latency
   - Error rates
   - DynamoDB performance

### Alerts

Set up alerts for:
- High error rates (>5%)
- Low feedback sentiment
- DynamoDB throttling
- Lambda timeout/errors

## Next Steps

### Phase 1 (Completed) ✅
- [x] Database schema design
- [x] Backend API implementation
- [x] Frontend components
- [x] Authentication/authorization
- [x] Tests
- [x] API documentation

### Phase 2 (Recommended)
- [ ] Admin dashboard for feedback management
- [ ] Email notifications for new feedback
- [ ] Advanced analytics and reporting
- [ ] Attachment support (screenshots)
- [ ] Feedback categorization using ML
- [ ] Integration with Jira/GitHub Issues

### Phase 3 (Future)
- [ ] Real-time notifications
- [ ] Feedback voting system
- [ ] Public roadmap based on feedback
- [ ] A/B testing framework
- [ ] Advanced user segmentation

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check JWT token validity
   - Verify Authorization header format
   - Ensure user is authenticated

2. **400 Bad Request**
   - Validate request payload
   - Check field constraints
   - Review validation error messages

3. **500 Internal Server Error**
   - Check DynamoDB table exists
   - Verify Lambda permissions
   - Review CloudWatch logs

### Debug Mode

Enable debug logging:
```bash
# Backend
export LOG_LEVEL=debug

# Frontend
localStorage.setItem('debug', 'true')
```

## Support

For issues or questions:
- Check CloudWatch Logs
- Review this documentation
- Contact: wmarusiak (resource owner)

## License

MIT License - See project LICENSE file
