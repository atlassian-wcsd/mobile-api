# Feedback System Integration Example

## Quick Start

### 1. Add Feedback Button to Your App

The simplest way to add feedback functionality is to include the `FeedbackButton` component:

```tsx
// In your main App component
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';
import { AppleUser } from './models/AppleUser';

function App() {
  const [user, setUser] = useState<AppleUser | null>(null);

  return (
    <div className="app">
      {/* Your existing app content */}
      
      {/* Add the floating feedback button */}
      <FeedbackButton
        position="bottom-right"
        userEmail={user?.email}
        onFeedbackSubmitted={(feedbackId) => {
          console.log('Feedback submitted:', feedbackId);
          // Optional: Show a success notification
        }}
      />
    </div>
  );
}
```

### 2. Environment Configuration

Add the API base URL to your environment variables:

```bash
# .env
REACT_APP_API_BASE_URL=https://your-api-gateway-url.amazonaws.com/Prod
```

### 3. Deploy Backend

The feedback endpoints are automatically deployed with your existing Lambda function. Make sure your `template.yml` includes the feedback routes (already added).

## Advanced Integration Examples

### Custom Feedback Trigger

```tsx
import { FeedbackForm } from './components/FeedbackForm';

function SettingsPage() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <div>
      <h2>Settings</h2>
      
      <button 
        onClick={() => setShowFeedback(true)}
        className="btn btn-primary"
      >
        Send Feedback
      </button>

      {showFeedback && (
        <div className="modal-overlay">
          <FeedbackForm
            onSuccess={(feedbackId) => {
              setShowFeedback(false);
              alert('Thank you for your feedback!');
            }}
            onError={(error) => {
              alert('Error: ' + error);
            }}
            onClose={() => setShowFeedback(false)}
            userEmail={user?.email}
          />
        </div>
      )}
    </div>
  );
}
```

### Programmatic Feedback Submission

```tsx
import { FeedbackService } from './services/FeedbackService';
import { FeedbackCategory } from './models/Feedback';

async function submitAutomaticFeedback() {
  const feedbackService = new FeedbackService();
  
  try {
    const response = await feedbackService.submitFeedback({
      rating: 4,
      category: FeedbackCategory.BUG_REPORT,
      subject: "Automatic error report",
      message: "An error occurred in the signature canvas",
      email: user?.email
    });

    if (response.success) {
      console.log('Error report submitted:', response.feedbackId);
    }
  } catch (error) {
    console.error('Failed to submit error report:', error);
  }
}
```

### Feedback History Display

```tsx
import { FeedbackService } from './services/FeedbackService';

function FeedbackHistory() {
  const [feedback, setFeedback] = useState([]);
  const [loading, setLoading] = useState(true);
  const feedbackService = new FeedbackService();

  useEffect(() => {
    async function loadFeedback() {
      try {
        const history = await feedbackService.getFeedbackHistory(user?.authToken);
        setFeedback(history);
      } catch (error) {
        console.error('Failed to load feedback history:', error);
      } finally {
        setLoading(false);
      }
    }

    if (user?.authToken) {
      loadFeedback();
    }
  }, [user]);

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h2>Your Feedback History</h2>
      {feedback.length === 0 ? (
        <p>No feedback submitted yet.</p>
      ) : (
        <div className="feedback-list">
          {feedback.map((item) => (
            <div key={item.id} className="feedback-item">
              <h3>{item.subject}</h3>
              <p>Rating: {'★'.repeat(item.rating)}</p>
              <p>Status: {item.status}</p>
              <p>Submitted: {new Date(item.createdAt).toLocaleDateString()}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

## Testing the Integration

### 1. Test Feedback Submission

```tsx
// Test component for development
function FeedbackTest() {
  const handleTest = async () => {
    const feedbackService = new FeedbackService();
    
    const testFeedback = {
      rating: 5,
      category: 'general_feedback',
      subject: 'Test feedback',
      message: 'This is a test feedback submission',
      email: 'test@example.com'
    };

    try {
      const response = await feedbackService.submitFeedback(testFeedback);
      console.log('Test result:', response);
    } catch (error) {
      console.error('Test failed:', error);
    }
  };

  return (
    <button onClick={handleTest}>
      Test Feedback Submission
    </button>
  );
}
```

### 2. Verify Backend

Check that your Lambda function is receiving requests:

```bash
# View CloudWatch logs
aws logs tail /aws/lambda/your-function-name --follow
```

### 3. Check DynamoDB

Verify feedback is being stored:

```bash
# List items in Feedback table
aws dynamodb scan --table-name Feedback --max-items 10
```

## Styling Integration

### Using with Existing CSS Framework

```tsx
// Bootstrap example
<FeedbackButton
  className="btn btn-primary"
  position="bottom-right"
/>

// Tailwind CSS example
<FeedbackButton
  className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
  position="bottom-right"
/>
```

### Custom Styling

```css
/* Custom styles for feedback components */
.feedback-button {
  background: linear-gradient(45deg, #007bff, #0056b3);
  box-shadow: 0 4px 15px rgba(0, 123, 255, 0.4);
  transition: all 0.3s ease;
}

.feedback-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(0, 123, 255, 0.6);
}

.feedback-form {
  font-family: 'Inter', sans-serif;
  max-width: 600px;
  margin: 0 auto;
}

.feedback-form .star-rating {
  font-size: 2rem;
  color: #ffd700;
}
```

## Error Handling

### Network Errors

```tsx
function FeedbackWithRetry() {
  const [retryCount, setRetryCount] = useState(0);
  const maxRetries = 3;

  const handleSubmit = async (feedbackData) => {
    try {
      const response = await feedbackService.submitFeedback(feedbackData);
      if (response.success) {
        setRetryCount(0);
        // Success handling
      }
    } catch (error) {
      if (retryCount < maxRetries) {
        setRetryCount(prev => prev + 1);
        setTimeout(() => handleSubmit(feedbackData), 1000 * retryCount);
      } else {
        // Show error to user
        alert('Failed to submit feedback. Please try again later.');
      }
    }
  };

  return (
    <FeedbackForm
      onSubmit={handleSubmit}
      // ... other props
    />
  );
}
```

### Offline Support

```tsx
function OfflineFeedback() {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [pendingFeedback, setPendingFeedback] = useState([]);

  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      // Submit pending feedback
      pendingFeedback.forEach(submitFeedback);
      setPendingFeedback([]);
    };

    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [pendingFeedback]);

  const handleFeedbackSubmit = (feedbackData) => {
    if (isOnline) {
      submitFeedback(feedbackData);
    } else {
      setPendingFeedback(prev => [...prev, feedbackData]);
      alert('Feedback saved. Will be submitted when online.');
    }
  };

  return (
    <FeedbackForm
      onSubmit={handleFeedbackSubmit}
      disabled={!isOnline}
      // ... other props
    />
  );
}
```

## Performance Optimization

### Lazy Loading

```tsx
import { lazy, Suspense } from 'react';

const FeedbackForm = lazy(() => import('./components/FeedbackForm'));

function App() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <div>
      {/* App content */}
      
      {showFeedback && (
        <Suspense fallback={<div>Loading feedback form...</div>}>
          <FeedbackForm
            onClose={() => setShowFeedback(false)}
            // ... other props
          />
        </Suspense>
      )}
    </div>
  );
}
```

### Debounced Validation

```tsx
import { useMemo } from 'react';
import { debounce } from 'lodash';

function FeedbackFormWithDebounce() {
  const [formData, setFormData] = useState({});
  const [errors, setErrors] = useState({});

  const debouncedValidation = useMemo(
    () => debounce((data) => {
      const validationErrors = FeedbackValidator.validateFeedback(data);
      setErrors(validationErrors);
    }, 300),
    []
  );

  const handleInputChange = (field, value) => {
    const newData = { ...formData, [field]: value };
    setFormData(newData);
    debouncedValidation(newData);
  };

  return (
    <FeedbackForm
      formData={formData}
      errors={errors}
      onInputChange={handleInputChange}
      // ... other props
    />
  );
}
```

## Monitoring and Analytics

### Track Feedback Events

```tsx
// Google Analytics example
import { gtag } from 'ga-gtag';

function trackFeedbackEvent(action, category, rating) {
  gtag('event', action, {
    event_category: 'feedback',
    event_label: category,
    value: rating
  });
}

// Usage in FeedbackForm
const handleSubmit = async (feedbackData) => {
  try {
    const response = await feedbackService.submitFeedback(feedbackData);
    if (response.success) {
      trackFeedbackEvent('submit', feedbackData.category, feedbackData.rating);
    }
  } catch (error) {
    trackFeedbackEvent('error', 'submission_failed', 0);
  }
};
```

### Custom Metrics

```tsx
// Send custom metrics to your analytics service
function sendFeedbackMetrics(feedbackData) {
  // Example: Send to your analytics service
  analytics.track('Feedback Submitted', {
    rating: feedbackData.rating,
    category: feedbackData.category,
    hasEmail: !!feedbackData.email,
    messageLength: feedbackData.message.length,
    timestamp: new Date().toISOString()
  });
}
```

This integration guide provides practical examples for implementing the feedback system in your application. Choose the approach that best fits your needs and customize as necessary.