# User Feedback System Documentation

## Overview

The User Feedback System is a comprehensive solution that allows users to submit feedback, bug reports, feature requests, and other types of input directly from within the application. The system supports both authenticated and anonymous feedback submission.

## Features

### Frontend Features
- **Feedback Form Modal**: A comprehensive form with validation and file upload support
- **Floating Feedback Button**: Always accessible feedback entry point
- **Multiple Feedback Types**: Bug reports, feature requests, general feedback, support requests, compliments, and complaints
- **Star Rating System**: Optional 1-5 star rating for feedback
- **File Attachments**: Support for images, PDFs, and text files (max 5MB each, up to 3 files)
- **Device Information Collection**: Automatic collection of browser and device information
- **Error Log Collection**: Automatic collection of application error logs
- **Real-time Validation**: Client-side validation with immediate feedback
- **Responsive Design**: Mobile-friendly interface

### Backend Features
- **RESTful API**: Clean API endpoints for feedback operations
- **DynamoDB Storage**: Scalable storage for feedback data
- **Authentication Support**: Works with Apple ID authentication
- **Anonymous Feedback**: Supports feedback submission without authentication
- **CORS Support**: Proper CORS headers for cross-origin requests
- **Input Validation**: Server-side validation and sanitization
- **Error Handling**: Comprehensive error handling and logging

## Architecture

### Frontend Components

#### 1. FeedbackForm Component
- **Location**: `src/components/FeedbackForm.tsx`
- **Purpose**: Main feedback submission form
- **Props**:
  - `isOpen`: Controls modal visibility
  - `onClose`: Callback for closing the modal
  - `onSuccess`: Callback for successful submission
  - `onError`: Callback for error handling
  - `authToken`: Optional authentication token
  - `userEmail`: Pre-filled email for authenticated users

#### 2. FeedbackButton Component
- **Location**: `src/components/FeedbackButton.tsx`
- **Purpose**: Floating feedback button
- **Props**:
  - `authToken`: Optional authentication token
  - `userEmail`: Pre-filled email for authenticated users
  - `position`: Button position (bottom-right, bottom-left, etc.)
  - `onFeedbackSubmitted`: Success callback
  - `onError`: Error callback

#### 3. FeedbackService
- **Location**: `src/services/FeedbackService.ts`
- **Purpose**: API communication and validation
- **Methods**:
  - `submitFeedback()`: Submit feedback to backend
  - `getFeedbackHistory()`: Get user's feedback history
  - `getFeedbackStatus()`: Get feedback status by ID
  - `uploadAttachment()`: Upload file attachments
  - `validateFeedbackRequest()`: Client-side validation

### Backend Components

#### 1. FeedbackHandler
- **Location**: `submitImage/opendevopslambda/feedback_handler.go`
- **Purpose**: Handle feedback API requests
- **Methods**:
  - `HandleSubmitFeedback()`: Process feedback submission
  - `HandleGetFeedbackHistory()`: Retrieve user feedback history
  - `HandleGetFeedbackStatus()`: Get feedback by ID
  - `HandleOptions()`: CORS preflight handling

#### 2. Data Models
- **Feedback**: Complete feedback record with metadata
- **FeedbackRequest**: Request payload for submission
- **FeedbackResponse**: Response structure for API calls

## API Endpoints

### POST /feedback/submit
Submit new feedback to the system.

**Request Body**:
```json
{
  "type": "bug_report",
  "category": "user_interface",
  "subject": "Button not working",
  "message": "The submit button doesn't respond when clicked",
  "rating": 3,
  "email": "user@example.com",
  "metadata": {
    "currentPage": "/signature",
    "sessionId": "abc123",
    "errorLogs": ["Error: Button click failed"],
    "attachments": ["https://s3.amazonaws.com/..."]
  }
}
```

**Response**:
```json
{
  "success": true,
  "feedbackId": "uuid-here",
  "message": "Feedback submitted successfully"
}
```

### GET /feedback/history
Retrieve feedback history for authenticated user.

**Query Parameters**:
- `limit`: Maximum number of entries (default: 10, max: 50)

**Response**:
```json
{
  "feedbacks": [
    {
      "id": "uuid-here",
      "type": "bug_report",
      "subject": "Button not working",
      "status": "submitted",
      "createdAt": "2023-12-01T10:00:00Z"
    }
  ]
}
```

### GET /feedback/{id}
Get feedback status by ID.

**Response**:
```json
{
  "feedback": {
    "id": "uuid-here",
    "type": "bug_report",
    "subject": "Button not working",
    "status": "in_progress",
    "createdAt": "2023-12-01T10:00:00Z"
  }
}
```

## Data Storage

### DynamoDB Table: UserFeedback

**Primary Key**: `Id` (String)

**Attributes**:
- `Id`: Unique feedback identifier (UUID)
- `UserId`: User identifier (optional for anonymous feedback)
- `Email`: Contact email (optional)
- `Type`: Feedback type (bug_report, feature_request, etc.)
- `Category`: Feedback category (user_interface, performance, etc.)
- `Subject`: Brief description
- `Message`: Detailed feedback message
- `Rating`: Star rating (1-5, optional)
- `DeviceInfo`: Browser and device information
- `AppVersion`: Application version
- `CreatedAt`: Timestamp (ISO 8601)
- `Status`: Current status (submitted, acknowledged, in_progress, resolved, closed)
- `Metadata`: Additional context (current page, session ID, error logs, attachments)

## Integration Guide

### 1. Basic Integration

Add the feedback button to your app:

```tsx
import { FeedbackButton } from './components/FeedbackButton';

function App() {
  return (
    <div>
      {/* Your app content */}
      <FeedbackButton />
    </div>
  );
}
```

### 2. With Authentication

Pass user information for better experience:

```tsx
<FeedbackButton
  authToken={user.authToken}
  userEmail={user.email}
  onFeedbackSubmitted={(feedbackId) => {
    console.log('Feedback submitted:', feedbackId);
  }}
  onError={(error) => {
    console.error('Feedback error:', error);
  }}
/>
```

### 3. Custom Positioning

```tsx
<FeedbackButton
  position="bottom-left"
  className="custom-feedback-button"
/>
```

### 4. Manual Form Control

```tsx
import { FeedbackForm } from './components/FeedbackForm';

function CustomComponent() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <>
      <button onClick={() => setShowFeedback(true)}>
        Give Feedback
      </button>
      
      <FeedbackForm
        isOpen={showFeedback}
        onClose={() => setShowFeedback(false)}
        onSuccess={(feedbackId) => {
          setShowFeedback(false);
          // Handle success
        }}
      />
    </>
  );
}
```

## Configuration

### Environment Variables

**Frontend** (`.env`):
```
REACT_APP_API_BASE_URL=https://your-api-gateway-url.com
REACT_APP_VERSION=1.0.0
```

**Backend** (AWS Lambda Environment Variables):
- Standard AWS SDK configuration
- DynamoDB table permissions
- S3 bucket permissions for file uploads

### AWS Resources

The system requires the following AWS resources:

1. **DynamoDB Table**: `UserFeedback`
   - Primary key: `Id` (String)
   - Billing mode: On-demand or Provisioned
   - Permissions: Read/Write access for Lambda function

2. **S3 Bucket**: For file attachments (optional)
   - Public read access for uploaded files
   - CORS configuration for frontend uploads

3. **Lambda Function**: Feedback handler
   - Runtime: Go 1.x
   - Permissions: DynamoDB and S3 access
   - API Gateway integration

## Validation Rules

### Client-side Validation
- **Subject**: 5-100 characters
- **Message**: 10-2000 characters
- **Email**: Valid email format (if provided)
- **Rating**: Integer between 1-5 (if provided)
- **File attachments**: Max 5MB each, up to 3 files
- **Supported file types**: Images (JPEG, PNG, GIF), PDF, text files

### Server-side Validation
- All client-side validations are repeated
- Input sanitization for XSS prevention
- File type and size verification
- Rate limiting (can be implemented)

## Error Handling

### Frontend Error Handling
- Network errors: Retry mechanism with exponential backoff
- Validation errors: Real-time feedback to user
- File upload errors: Clear error messages
- Authentication errors: Graceful degradation to anonymous mode

### Backend Error Handling
- Input validation errors: 400 Bad Request
- Authentication errors: 401 Unauthorized
- Not found errors: 404 Not Found
- Server errors: 500 Internal Server Error
- Comprehensive logging for debugging

## Security Considerations

1. **Input Sanitization**: All user inputs are sanitized
2. **File Upload Security**: File type and size validation
3. **CORS Configuration**: Proper CORS headers
4. **Authentication**: Optional but secure token validation
5. **Rate Limiting**: Can be implemented at API Gateway level
6. **Data Privacy**: No sensitive data stored without consent

## Monitoring and Analytics

### Metrics to Track
- Feedback submission rate
- Feedback types distribution
- User satisfaction ratings
- Response times
- Error rates

### Logging
- All feedback submissions are logged
- Error conditions are logged with context
- Performance metrics are available through AWS CloudWatch

## Customization Options

### Styling
- CSS classes can be overridden
- Custom themes can be applied
- Responsive design adapts to different screen sizes

### Functionality
- Custom validation rules
- Additional feedback types
- Custom metadata collection
- Integration with external systems (email, Slack, etc.)

## Troubleshooting

### Common Issues

1. **Feedback not submitting**
   - Check network connectivity
   - Verify API endpoint configuration
   - Check browser console for errors

2. **File upload failing**
   - Verify file size and type
   - Check S3 bucket permissions
   - Verify CORS configuration

3. **Authentication issues**
   - Verify token format and expiration
   - Check authentication service integration

### Debug Mode
Enable debug logging by setting `localStorage.setItem('feedback_debug', 'true')` in the browser console.

## Future Enhancements

1. **Admin Dashboard**: Web interface for managing feedback
2. **Email Notifications**: Automatic notifications for new feedback
3. **Feedback Analytics**: Advanced reporting and analytics
4. **Integration APIs**: Webhooks for external systems
5. **Mobile App Support**: React Native components
6. **Offline Support**: Queue feedback when offline
7. **Multi-language Support**: Internationalization
8. **Advanced File Support**: More file types and larger sizes

## Support

For technical support or questions about the feedback system:
1. Check this documentation
2. Review the code comments
3. Check the API logs in AWS CloudWatch
4. Submit feedback using the system itself!