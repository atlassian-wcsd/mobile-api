# User Feedback System Documentation

## Overview

The User Feedback System is a comprehensive solution that allows users to submit feedback, bug reports, feature requests, and general comments about the application. The system includes both frontend React components and backend Go services with AWS infrastructure.

## Architecture

### Frontend Components
- **FeedbackForm**: Main form component for collecting user feedback
- **FeedbackButton**: Trigger button that can be placed anywhere in the app
- **FeedbackService**: Service class for API communication
- **Feedback Models**: TypeScript interfaces and types

### Backend Services
- **FeedbackHandler**: Go HTTP handler for feedback endpoints
- **FeedbackService**: Go service for business logic and data operations
- **Feedback Models**: Go structs and types

### Infrastructure
- **DynamoDB Table**: `UserFeedback` table for storing feedback data
- **API Gateway**: RESTful endpoints for feedback operations
- **Lambda Function**: Serverless compute for handling requests

## Features

### ✅ Implemented Features

1. **Feedback Submission**
   - Multiple feedback types (bug reports, feature requests, etc.)
   - Star rating system (1-5 stars)
   - Rich text feedback with character limits
   - Optional contact information
   - Automatic metadata collection

2. **User Interface**
   - Modal and inline form options
   - Responsive design for mobile and desktop
   - Real-time validation
   - Loading states and error handling
   - Floating action button for easy access

3. **Backend API**
   - RESTful endpoints for all operations
   - Input validation and sanitization
   - CORS support for cross-origin requests
   - Error handling and logging

4. **Data Storage**
   - DynamoDB for scalable storage
   - Global Secondary Index for user queries
   - Point-in-time recovery enabled
   - Automatic metadata enrichment

5. **Admin Features**
   - Get all feedback endpoint
   - Feedback statistics
   - Status management (new, in_review, resolved, closed)

## API Endpoints

### Public Endpoints

#### Submit Feedback
```
POST /feedback
Content-Type: application/json

{
  "email": "user@example.com",
  "name": "John Doe",
  "type": "bug_report",
  "rating": 4,
  "subject": "Issue with signature canvas",
  "message": "The signature canvas doesn't work on mobile devices...",
  "page": "/signature",
  "metadata": {
    "appVersion": "1.0.0",
    "screenResolution": "1920x1080"
  }
}
```

#### Get Feedback by ID
```
GET /feedback/{feedbackId}
```

#### Get User Feedback
```
GET /feedback/user?userId={userId}
```

### Admin Endpoints

#### Get All Feedback
```
GET /feedback/admin/all?limit=100
```

#### Get Feedback Statistics
```
GET /feedback/admin/stats
```

## Frontend Usage

### Basic Implementation

```tsx
import React, { useState } from 'react';
import { FeedbackButton } from './components/FeedbackButton';

function App() {
  const [user, setUser] = useState(null);

  return (
    <div>
      {/* Your app content */}
      
      {/* Floating feedback button */}
      <FeedbackButton
        floating={true}
        position="bottom-right"
        userInfo={user ? {
          userId: user.id,
          email: user.email,
          name: user.fullName
        } : undefined}
        onFeedbackSubmitted={(feedbackId) => {
          console.log('Feedback submitted:', feedbackId);
        }}
        onFeedbackError={(error) => {
          console.error('Feedback error:', error);
        }}
      />
    </div>
  );
}
```

### Inline Form Implementation

```tsx
import React, { useState } from 'react';
import { FeedbackForm } from './components/FeedbackForm';

function SettingsPage() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <div>
      <h1>Settings</h1>
      
      <button onClick={() => setShowFeedback(true)}>
        Send Feedback
      </button>

      <FeedbackForm
        isOpen={showFeedback}
        onClose={() => setShowFeedback(false)}
        modal={false} // Inline form
        userInfo={{
          userId: 'user123',
          email: 'user@example.com',
          name: 'John Doe'
        }}
      />
    </div>
  );
}
```

### Custom Service Usage

```tsx
import { FeedbackService } from './services/FeedbackService';
import { FeedbackType } from './models/Feedback';

const feedbackService = new FeedbackService();

// Submit feedback programmatically
const submitFeedback = async () => {
  const response = await feedbackService.submitFeedback({
    type: FeedbackType.FEATURE_REQUEST,
    rating: 5,
    subject: 'Add dark mode',
    message: 'Please add a dark mode option to the app.',
    email: 'user@example.com'
  });

  if (response.success) {
    console.log('Feedback submitted:', response.feedbackId);
  } else {
    console.error('Error:', response.error);
  }
};
```

## Configuration

### Environment Variables

#### Frontend (.env)
```
REACT_APP_API_BASE_URL=https://your-api-gateway-url.com/v1
REACT_APP_VERSION=1.0.0
```

#### Backend (AWS Lambda Environment Variables)
```
APPLE_CLIENT_ID=your.app.bundle.id
APPLE_TEAM_ID=your_team_id
APPLE_KEY_ID=your_key_id
APPLE_PRIVATE_KEY=your_private_key
```

### AWS Infrastructure

The feedback system requires the following AWS resources:

1. **DynamoDB Table**: `UserFeedback`
   - Primary Key: `id` (String)
   - GSI: `UserIdIndex` with `userId` and `createdAt`

2. **Lambda Function**: Handles all feedback operations

3. **API Gateway**: Provides RESTful endpoints

4. **IAM Roles**: Appropriate permissions for DynamoDB access

## Data Models

### Feedback Object
```typescript
interface Feedback {
  id: string;
  userId?: string;
  email?: string;
  name?: string;
  type: FeedbackType;
  rating: number; // 1-5
  subject: string; // max 200 chars
  message: string; // max 2000 chars
  page?: string;
  userAgent?: string;
  createdAt: Date;
  status: FeedbackStatus;
  metadata?: {
    appVersion?: string;
    screenResolution?: string;
    timestamp?: string;
    url?: string;
    context?: Record<string, any>;
  };
}
```

### Feedback Types
- `bug_report`: Bug reports and issues
- `feature_request`: New feature suggestions
- `general_feedback`: General comments and feedback
- `usability_issue`: User experience problems
- `performance_issue`: Performance-related feedback
- `other`: Other types of feedback

### Feedback Status
- `new`: Newly submitted feedback
- `in_review`: Being reviewed by the team
- `resolved`: Issue has been resolved
- `closed`: Feedback has been closed

## Security Considerations

1. **Input Validation**: All inputs are validated on both frontend and backend
2. **Rate Limiting**: Consider implementing rate limiting for feedback submission
3. **Authentication**: User feedback endpoints can be protected with authentication
4. **Data Privacy**: Email addresses and personal information are handled securely
5. **CORS**: Properly configured for cross-origin requests

## Monitoring and Analytics

### Metrics to Track
- Feedback submission rate
- Feedback types distribution
- Average rating scores
- Response times
- Error rates

### Logging
- All feedback submissions are logged
- Error conditions are logged with context
- User actions are tracked for analytics

## Deployment

### Frontend Deployment
1. Build the React application: `npm run build`
2. Deploy to your hosting platform (S3, Netlify, Vercel, etc.)
3. Configure environment variables

### Backend Deployment
1. Update `template.yml` with your configuration
2. Deploy using AWS SAM: `sam deploy --guided`
3. Configure environment variables in Lambda

### Database Setup
The DynamoDB table is automatically created during deployment with the SAM template.

## Testing

### Frontend Testing
```bash
# Run unit tests
npm test

# Run integration tests
npm run test:integration
```

### Backend Testing
```bash
# Run Go tests
cd submitImage
go test ./...

# Run specific test
go test ./services -v
```

### Manual Testing
1. Test feedback submission with various inputs
2. Verify validation errors are handled correctly
3. Test responsive design on different devices
4. Verify admin endpoints work correctly

## Troubleshooting

### Common Issues

1. **CORS Errors**
   - Ensure API Gateway has proper CORS configuration
   - Check that frontend URL is allowed

2. **DynamoDB Access Denied**
   - Verify Lambda execution role has DynamoDB permissions
   - Check table name matches configuration

3. **Validation Errors**
   - Check input field requirements
   - Verify character limits are respected

4. **Form Not Submitting**
   - Check network connectivity
   - Verify API endpoint URLs
   - Check browser console for errors

### Debug Mode
Enable debug logging by setting environment variables:
```
DEBUG=true
LOG_LEVEL=debug
```

## Future Enhancements

### Planned Features
1. **Email Notifications**: Notify admins of new feedback
2. **Feedback Dashboard**: Admin interface for managing feedback
3. **Attachment Support**: Allow users to attach screenshots
4. **Feedback Categories**: More granular categorization
5. **Response System**: Allow admins to respond to feedback
6. **Analytics Dashboard**: Detailed feedback analytics
7. **Integration**: Slack/Teams notifications
8. **Mobile App**: Native mobile app support

### Performance Optimizations
1. **Caching**: Implement caching for frequently accessed data
2. **Pagination**: Add pagination for large feedback lists
3. **Search**: Full-text search capabilities
4. **Archiving**: Archive old feedback to improve performance

## Support

For questions or issues with the feedback system:

1. Check this documentation first
2. Review the API specification in `api.yaml`
3. Check the application logs
4. Submit a bug report using the feedback system itself!

## Contributing

When contributing to the feedback system:

1. Follow the existing code patterns
2. Add appropriate tests
3. Update documentation
4. Ensure backward compatibility
5. Test thoroughly before submitting

---

*Last updated: December 2024*