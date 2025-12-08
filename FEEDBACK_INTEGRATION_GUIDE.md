# Feedback Form Integration Guide

## Quick Start

### Step 1: Add Frontend Components

The feedback form components are ready to use in `src/components/`:

- `FeedbackForm.tsx` - Main feedback form component
- `FeedbackButton.tsx` - Floating button trigger
- `FeedbackForm.css` - Form styling
- `FeedbackButton.css` - Button and modal styling

### Step 2: Integrate into Your App

**Option A: Use the Floating Button (Recommended)**

```tsx
// In your main App component
import { FeedbackButton } from './components/FeedbackButton';

export function App() {
  const userId = getCurrentUserId(); // From authentication context

  return (
    <div className="app-container">
      {/* Your app content */}
      <Header />
      <MainContent />
      <Footer />
      
      {/* Add feedback button */}
      <FeedbackButton
        userId={userId}
        position="bottom-right"
        onFeedbackSubmitted={(feedbackId) => {
          console.log('Feedback submitted:', feedbackId);
          // Optional: track analytics or show confirmation
        }}
      />
    </div>
  );
}
```

**Option B: Use the Form in a Modal**

```tsx
import { FeedbackForm } from './components/FeedbackForm';
import { useState } from 'react';

export function App() {
  const [showFeedback, setShowFeedback] = useState(false);
  const userId = getCurrentUserId();

  return (
    <>
      {/* Your app content */}
      
      {/* Feedback button/menu item */}
      <button onClick={() => setShowFeedback(true)}>Send Feedback</button>
      
      {/* Feedback form modal */}
      {showFeedback && (
        <div className="modal-overlay">
          <FeedbackForm
            userId={userId}
            onSubmitSuccess={(feedbackId) => {
              setShowFeedback(false);
              // Optional: show success toast
            }}
            onSubmitError={(error) => {
              console.error('Feedback error:', error);
            }}
            onClose={() => setShowFeedback(false)}
          />
        </div>
      )}
    </>
  );
}
```

### Step 3: Set Up Backend Services

#### Install Dependencies

```bash
cd submitImage
go get github.com/google/uuid
go get github.com/gorilla/mux
```

#### Create Main Handler

In your `submitImage/main.go` or `submitImage/opendevopslambda/lambda.go`:

```go
package main

import (
  "net/http"
  "submitImage/feedback"
)

func init() {
  // Initialize feedback store
  feedbackStore := feedback.NewInMemoryFeedbackStore()
  
  // Create feedback handler
  feedbackHandler := feedback.NewFeedbackHandler(feedbackStore)
  
  // Register routes
  mux := http.NewServeMux()
  
  // Feedback endpoints
  mux.HandleFunc("POST /api/feedback", feedbackHandler.SubmitFeedbackHandler)
  mux.HandleFunc("GET /api/feedback/", feedbackHandler.GetFeedbackHandler)
  mux.HandleFunc("GET /api/user/", feedbackHandler.GetUserFeedbackHandler)
  mux.HandleFunc("GET /api/admin/feedback", feedbackHandler.GetAllFeedbackHandler)
  mux.HandleFunc("GET /api/feedback/category/", feedbackHandler.GetFeedbackByCategoryHandler)
  mux.HandleFunc("PUT /api/feedback/", feedbackHandler.UpdateFeedbackStatusHandler)
  mux.HandleFunc("GET /api/admin/feedback/statistics", feedbackHandler.GetStatisticsHandler)
}
```

#### For AWS Lambda

```go
package main

import (
  "context"
  "github.com/aws/aws-lambda-go/events"
  "github.com/aws/aws-lambda-go/lambda"
  "submitImage/feedback"
)

var feedbackStore feedback.FeedbackStore
var feedbackHandler *feedback.FeedbackHandler

func init() {
  feedbackStore = feedback.NewInMemoryFeedbackStore()
  feedbackHandler = feedback.NewFeedbackHandler(feedbackStore)
}

func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  // Route requests to appropriate handler
  switch request.HTTPMethod {
  case "POST":
    if request.Path == "/api/feedback" {
      // Handle feedback submission
    }
  case "GET":
    // Handle GET requests
  }
  
  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Body:       "Success",
  }, nil
}

func main() {
  lambda.Start(HandleRequest)
}
```

### Step 4: Configure API Communication

Update your API client configuration:

```typescript
// src/services/ApiClient.ts (or similar)

export const submitFeedback = async (
  userId: string,
  feedbackData: {
    message: string;
    rating: number;
    category?: string;
    contactInfo?: string;
  }
): Promise<{ feedbackId: string }> => {
  const response = await fetch('/api/feedback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-User-ID': userId,
      // Add any authentication headers if needed
      // 'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(feedbackData),
  });

  if (!response.ok) {
    throw new Error(`Failed to submit feedback: ${response.statusText}`);
  }

  return response.json();
};

export const getUserFeedback = async (userId: string) => {
  const response = await fetch(`/api/user/${userId}/feedback`);
  
  if (!response.ok) {
    throw new Error('Failed to fetch feedback');
  }
  
  return response.json();
};

export const getAllFeedback = async (status?: string) => {
  const url = new URL('/api/admin/feedback', window.location.origin);
  if (status) {
    url.searchParams.append('status', status);
  }
  
  const response = await fetch(url.toString());
  
  if (!response.ok) {
    throw new Error('Failed to fetch feedback');
  }
  
  return response.json();
};

export const getFeedbackStatistics = async () => {
  const response = await fetch('/api/admin/feedback/statistics');
  
  if (!response.ok) {
    throw new Error('Failed to fetch statistics');
  }
  
  return response.json();
};
```

### Step 5: Update FeedbackService to Use API

Modify `src/services/FeedbackService.ts` to communicate with backend:

```typescript
import { Feedback, FeedbackSubmissionRequest } from '../models/Feedback';
import * as ApiClient from './ApiClient';

export class FeedbackService {
  /**
   * Submit feedback to the backend
   */
  public async submitFeedbackToServer(
    userId: string,
    feedbackData: FeedbackSubmissionRequest
  ): Promise<string> {
    try {
      const response = await ApiClient.submitFeedback(userId, feedbackData);
      return response.feedbackId;
    } catch (error) {
      throw new Error(
        error instanceof Error ? error.message : 'Failed to submit feedback'
      );
    }
  }

  /**
   * Get user's feedback from server
   */
  public async getUserFeedbackFromServer(userId: string): Promise<Feedback[]> {
    return ApiClient.getUserFeedback(userId);
  }

  /**
   * Get statistics (admin)
   */
  public async getStatisticsFromServer() {
    return ApiClient.getFeedbackStatistics();
  }
}
```

### Step 6: Update FeedbackForm Component

Modify `FeedbackForm.tsx` to use the API:

```typescript
// In the handleSubmit method
const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
  event.preventDefault();
  setErrors([]);
  setSubmitMessage(null);

  // Validate feedback
  const validation = feedbackService.validateFeedback(message, rating);
  if (!validation.valid) {
    setErrors(validation.errors);
    if (onSubmitError) {
      onSubmitError(validation.errors.join(', '));
    }
    return;
  }

  setIsSubmitting(true);

  try {
    // Submit to server
    const feedbackId = await feedbackService.submitFeedbackToServer(userId, {
      message,
      rating,
      contactInfo: contactInfo || undefined,
      category,
    });

    setSubmitMessage({
      type: 'success',
      text: 'Thank you! Your feedback has been submitted successfully.',
    });

    // Reset form
    setMessage('');
    setRating(0);
    setContactInfo('');
    setCategory('general');

    if (onSubmitSuccess) {
      onSubmitSuccess(feedbackId);
    }

    // Auto-close after success message
    setTimeout(() => {
      if (onClose) {
        onClose();
      }
    }, 2000);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to submit feedback';
    setSubmitMessage({
      type: 'error',
      text: errorMessage,
    });

    if (onSubmitError) {
      onSubmitError(errorMessage);
    }
  } finally {
    setIsSubmitting(false);
  }
};
```

### Step 7: Run Tests

**Frontend tests:**
```bash
npm test
```

**Backend tests:**
```bash
cd submitImage
go test ./feedback -v
```

### Step 8: Deploy

**Frontend:**
```bash
npm run build
```

**Backend:**
```bash
# For local testing
cd submitImage
go run main.go

# For AWS Lambda
serverless deploy
```

## Configuration Options

### Environment Variables

```bash
# .env or deployment config
FEEDBACK_API_URL=https://api.example.com
FEEDBACK_ENABLE_ANALYTICS=true
FEEDBACK_RETENTION_DAYS=90
```

### Component Customization

**Button Position:**
```tsx
<FeedbackButton position="bottom-left" />  // Default: bottom-right
<FeedbackButton position="top-right" />
<FeedbackButton position="top-left" />
```

**Custom Styling:**

Override CSS variables in your styles:
```css
:root {
  --feedback-primary-color: #4CAF50;
  --feedback-border-radius: 8px;
  --feedback-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
```

## Admin Dashboard Integration

For displaying feedback to support teams:

```typescript
// Admin page component
import { FeedbackService } from './services/FeedbackService';

export function AdminFeedbackDashboard() {
  const [feedback, setFeedback] = useState([]);
  const [stats, setStats] = useState(null);
  const feedbackService = new FeedbackService();

  useEffect(() => {
    const loadData = async () => {
      const allFeedback = await feedbackService.getUserFeedbackFromServer('admin');
      const statistics = await feedbackService.getStatisticsFromServer();
      
      setFeedback(allFeedback);
      setStats(statistics);
    };
    
    loadData();
  }, []);

  return (
    <div className="feedback-dashboard">
      <h1>User Feedback Dashboard</h1>
      
      {stats && (
        <div className="stats">
          <p>Total Feedback: {stats.totalFeedback}</p>
          <p>Average Rating: {stats.averageRating.toFixed(2)}/5</p>
        </div>
      )}
      
      <div className="feedback-list">
        {feedback.map(fb => (
          <div key={fb.id} className="feedback-item">
            <p>Rating: {fb.rating}/5</p>
            <p>Message: {fb.message}</p>
            <p>Category: {fb.category}</p>
            <p>Status: {fb.status}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
```

## Analytics Integration

### Google Analytics

```typescript
// Track feedback submission
const handleFeedbackSuccess = (feedbackId: string) => {
  if (window.gtag) {
    window.gtag('event', 'feedback_submitted', {
      feedback_id: feedbackId,
      rating: rating,
      category: category,
    });
  }
};
```

### Custom Analytics

```typescript
// In FeedbackForm.tsx
const trackFeedbackMetric = (eventName: string, data: any) => {
  // Send to your analytics service
  fetch('/api/analytics', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event: eventName, ...data }),
  });
};
```

## Troubleshooting Deployment

### Issue: CORS errors
**Solution:** Add CORS headers to your API responses:
```go
w.Header().Set("Access-Control-Allow-Origin", "*")
w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT")
w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-User-ID")
```

### Issue: User ID not being sent
**Solution:** Ensure FeedbackForm receives userId prop:
```tsx
<FeedbackForm userId={currentUserId} />
```

### Issue: Form not showing success/error messages
**Solution:** Check onSubmitSuccess/onSubmitError callbacks are passed and working.

### Issue: Tests failing after API integration
**Solution:** Mock the API calls in tests:
```typescript
jest.mock('./services/ApiClient', () => ({
  submitFeedback: jest.fn().mockResolvedValue({ feedbackId: 'test-id' }),
}));
```

## Next Steps

1. ✅ Implement frontend components
2. ✅ Create backend services
3. ✅ Set up API endpoints
4. ✅ Add validation and error handling
5. ✅ Write tests
6. ✅ Create documentation
7. **TODO**: Deploy to staging environment
8. **TODO**: Set up monitoring and alerting
9. **TODO**: Create admin dashboard
10. **TODO**: Plan analytics implementation

## Support

For questions or issues:
1. Review the FEEDBACK_FORM_IMPLEMENTATION.md document
2. Check test files for usage examples
3. Review component props and interfaces
4. Contact the development team

---

**Last Updated:** 2025-01-15
**Maintained By:** Development Team
