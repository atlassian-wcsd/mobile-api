# Feedback System Integration Examples

This document provides practical examples of how to integrate the feedback system into your application.

## Quick Start

### 1. Basic Floating Feedback Button

The simplest way to add feedback to your app:

```tsx
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';

function App() {
  return (
    <div>
      {/* Your app content */}
      <h1>My App</h1>
      
      {/* Floating feedback button - appears in bottom-right corner */}
      <FeedbackButton
        floating={true}
        position="bottom-right"
        onFeedbackSubmitted={(feedbackId) => {
          console.log('Feedback submitted:', feedbackId);
          // Optional: Show success notification
        }}
        onFeedbackError={(error) => {
          console.error('Feedback error:', error);
          // Optional: Show error notification
        }}
      />
    </div>
  );
}
```

### 2. Inline Feedback Form

For dedicated feedback pages or sections:

```tsx
import React, { useState } from 'react';
import { FeedbackForm } from './components/FeedbackForm';

function FeedbackPage() {
  const [isFormVisible, setIsFormVisible] = useState(true);

  return (
    <div style={{ padding: '2rem' }}>
      <h1>Send Us Your Feedback</h1>
      <p>We value your input and want to hear from you!</p>
      
      <FeedbackForm
        isOpen={isFormVisible}
        onClose={() => setIsFormVisible(false)}
        modal={false} // Inline form, not modal
        onSuccess={(feedbackId) => {
          alert(`Thank you! Your feedback ID is: ${feedbackId}`);
          setIsFormVisible(false);
        }}
        onError={(error) => {
          alert(`Error: ${error}`);
        }}
      />
    </div>
  );
}
```

## Advanced Integration Examples

### 3. Context-Aware Feedback

Automatically include page context and user information:

```tsx
import React, { useContext } from 'react';
import { FeedbackButton } from './components/FeedbackButton';
import { UserContext } from './contexts/UserContext';

function AppWithContext() {
  const { user } = useContext(UserContext);

  return (
    <div>
      {/* Your app content */}
      
      <FeedbackButton
        floating={true}
        userInfo={user ? {
          userId: user.id,
          email: user.email,
          name: user.displayName
        } : undefined}
        onFeedbackSubmitted={(feedbackId) => {
          // Track feedback submission in analytics
          analytics.track('feedback_submitted', {
            feedbackId,
            userId: user?.id,
            page: window.location.pathname
          });
        }}
      />
    </div>
  );
}
```

### 4. Custom Trigger Button

Create your own trigger button with custom styling:

```tsx
import React, { useState } from 'react';
import { FeedbackForm } from './components/FeedbackForm';

function CustomFeedbackTrigger() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <>
      {/* Custom trigger button */}
      <button
        onClick={() => setShowFeedback(true)}
        style={{
          backgroundColor: '#007bff',
          color: 'white',
          border: 'none',
          padding: '10px 20px',
          borderRadius: '5px',
          cursor: 'pointer'
        }}
      >
        💬 Feedback
      </button>

      {/* Feedback form modal */}
      <FeedbackForm
        isOpen={showFeedback}
        onClose={() => setShowFeedback(false)}
        onSuccess={(feedbackId) => {
          setShowFeedback(false);
          // Show success message
        }}
      />
    </>
  );
}
```

### 5. Multiple Feedback Entry Points

Different feedback buttons for different contexts:

```tsx
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';

function AppWithMultipleFeedback() {
  return (
    <div>
      {/* Header feedback - for general app feedback */}
      <header>
        <nav>
          <FeedbackButton
            text="Feedback"
            size="small"
            variant="outline"
            onFeedbackSubmitted={(id) => console.log('Header feedback:', id)}
          />
        </nav>
      </header>

      {/* Main content */}
      <main>
        <h1>Feature Page</h1>
        
        {/* Feature-specific feedback */}
        <section>
          <h2>New Feature</h2>
          <p>Try our new feature!</p>
          <FeedbackButton
            text="Feedback on this feature"
            variant="secondary"
            userInfo={{ /* pre-fill context */ }}
          />
        </section>
      </main>

      {/* Floating general feedback */}
      <FeedbackButton
        floating={true}
        position="bottom-right"
      />
    </div>
  );
}
```

### 6. Programmatic Feedback Submission

Submit feedback programmatically without showing the form:

```tsx
import React from 'react';
import { FeedbackService } from './services/FeedbackService';
import { FeedbackType } from './models/Feedback';

function ProgrammaticFeedback() {
  const feedbackService = new FeedbackService();

  const submitAutomaticFeedback = async () => {
    try {
      const response = await feedbackService.submitFeedback({
        type: FeedbackType.BUG_REPORT,
        rating: 1,
        subject: 'Automatic error report',
        message: 'An error occurred in the application',
        metadata: {
          errorCode: 'ERR_001',
          stackTrace: 'Error stack trace...',
          userAgent: navigator.userAgent
        }
      });

      if (response.success) {
        console.log('Error report submitted:', response.feedbackId);
      }
    } catch (error) {
      console.error('Failed to submit error report:', error);
    }
  };

  return (
    <button onClick={submitAutomaticFeedback}>
      Report Error
    </button>
  );
}
```

### 7. Feedback with File Attachments (Future Enhancement)

Example of how file attachments could be implemented:

```tsx
import React, { useState } from 'react';
import { FeedbackForm } from './components/FeedbackForm';

function FeedbackWithAttachments() {
  const [showFeedback, setShowFeedback] = useState(false);

  const handleScreenshot = async () => {
    // Capture screenshot (using a library like html2canvas)
    const canvas = await html2canvas(document.body);
    const screenshot = canvas.toDataURL();
    
    // Open feedback form with screenshot attached
    setShowFeedback(true);
    // Pass screenshot data to form (future enhancement)
  };

  return (
    <>
      <button onClick={handleScreenshot}>
        📸 Send Feedback with Screenshot
      </button>

      <FeedbackForm
        isOpen={showFeedback}
        onClose={() => setShowFeedback(false)}
        // attachments={[screenshot]} // Future enhancement
      />
    </>
  );
}
```

## Integration with Popular Frameworks

### React Router Integration

```tsx
import React from 'react';
import { useLocation } from 'react-router-dom';
import { FeedbackButton } from './components/FeedbackButton';

function AppWithRouter() {
  const location = useLocation();

  return (
    <div>
      {/* Your routes */}
      
      <FeedbackButton
        floating={true}
        // Automatically include current route in feedback
        onFeedbackSubmitted={(feedbackId) => {
          console.log('Feedback from page:', location.pathname);
        }}
      />
    </div>
  );
}
```

### Redux Integration

```tsx
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { FeedbackButton } from './components/FeedbackButton';
import { showNotification } from './store/notificationSlice';

function AppWithRedux() {
  const user = useSelector(state => state.auth.user);
  const dispatch = useDispatch();

  return (
    <div>
      <FeedbackButton
        floating={true}
        userInfo={user}
        onFeedbackSubmitted={(feedbackId) => {
          dispatch(showNotification({
            type: 'success',
            message: `Feedback submitted successfully! ID: ${feedbackId}`
          }));
        }}
        onFeedbackError={(error) => {
          dispatch(showNotification({
            type: 'error',
            message: `Failed to submit feedback: ${error}`
          }));
        }}
      />
    </div>
  );
}
```

### Next.js Integration

```tsx
// pages/_app.tsx
import React from 'react';
import type { AppProps } from 'next/app';
import { FeedbackButton } from '../components/FeedbackButton';

function MyApp({ Component, pageProps }: AppProps) {
  return (
    <>
      <Component {...pageProps} />
      
      {/* Global feedback button */}
      <FeedbackButton
        floating={true}
        position="bottom-right"
        onFeedbackSubmitted={(feedbackId) => {
          // Track with Next.js analytics
          if (typeof window !== 'undefined') {
            gtag('event', 'feedback_submitted', {
              feedback_id: feedbackId
            });
          }
        }}
      />
    </>
  );
}

export default MyApp;
```

## Styling and Customization

### Custom CSS Classes

```tsx
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';
import './custom-feedback.css';

function StyledFeedback() {
  return (
    <FeedbackButton
      className="my-custom-feedback-button"
      style={{
        backgroundColor: '#ff6b6b',
        borderRadius: '25px',
        boxShadow: '0 4px 15px rgba(255, 107, 107, 0.3)'
      }}
    />
  );
}
```

```css
/* custom-feedback.css */
.my-custom-feedback-button {
  transition: all 0.3s ease;
  font-weight: bold;
}

.my-custom-feedback-button:hover {
  transform: scale(1.05);
  box-shadow: 0 6px 20px rgba(255, 107, 107, 0.4) !important;
}
```

### Themed Feedback Button

```tsx
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';

function ThemedFeedback({ theme }) {
  const themeStyles = {
    light: {
      backgroundColor: '#ffffff',
      color: '#333333',
      border: '2px solid #e0e0e0'
    },
    dark: {
      backgroundColor: '#2c3e50',
      color: '#ffffff',
      border: '2px solid #34495e'
    }
  };

  return (
    <FeedbackButton
      style={themeStyles[theme]}
      text={theme === 'dark' ? '🌙 Feedback' : '☀️ Feedback'}
    />
  );
}
```

## Error Handling and Monitoring

### Comprehensive Error Handling

```tsx
import React from 'react';
import { FeedbackButton } from './components/FeedbackButton';

function RobustFeedback() {
  const handleFeedbackError = (error: string) => {
    // Log error to monitoring service
    console.error('Feedback submission failed:', error);
    
    // Track error in analytics
    if (window.gtag) {
      window.gtag('event', 'feedback_error', {
        error_message: error
      });
    }
    
    // Show user-friendly error message
    alert('Sorry, we couldn\'t submit your feedback right now. Please try again later.');
    
    // Optionally, store feedback locally for retry
    const failedFeedback = {
      timestamp: new Date().toISOString(),
      error,
      page: window.location.href
    };
    localStorage.setItem('failed_feedback', JSON.stringify(failedFeedback));
  };

  return (
    <FeedbackButton
      floating={true}
      onFeedbackError={handleFeedbackError}
      onFeedbackSubmitted={(feedbackId) => {
        // Clear any stored failed feedback on success
        localStorage.removeItem('failed_feedback');
        
        // Track successful submission
        if (window.gtag) {
          window.gtag('event', 'feedback_success', {
            feedback_id: feedbackId
          });
        }
      }}
    />
  );
}
```

## Performance Optimization

### Lazy Loading

```tsx
import React, { lazy, Suspense, useState } from 'react';

// Lazy load the feedback form to reduce initial bundle size
const FeedbackForm = lazy(() => import('./components/FeedbackForm'));

function OptimizedFeedback() {
  const [showFeedback, setShowFeedback] = useState(false);

  return (
    <>
      <button onClick={() => setShowFeedback(true)}>
        Feedback
      </button>

      {showFeedback && (
        <Suspense fallback={<div>Loading feedback form...</div>}>
          <FeedbackForm
            isOpen={showFeedback}
            onClose={() => setShowFeedback(false)}
          />
        </Suspense>
      )}
    </>
  );
}
```

### Debounced Validation

```tsx
import React, { useState, useCallback } from 'react';
import { debounce } from 'lodash';
import { FeedbackService } from './services/FeedbackService';

function OptimizedFeedbackForm() {
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');
  
  const feedbackService = new FeedbackService();

  // Debounce email validation to avoid excessive API calls
  const validateEmail = useCallback(
    debounce(async (emailValue: string) => {
      if (emailValue && !feedbackService.isValidEmail(emailValue)) {
        setEmailError('Invalid email format');
      } else {
        setEmailError('');
      }
    }, 300),
    []
  );

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEmail(value);
    validateEmail(value);
  };

  return (
    <div>
      <input
        type="email"
        value={email}
        onChange={handleEmailChange}
        placeholder="Your email"
      />
      {emailError && <span style={{ color: 'red' }}>{emailError}</span>}
    </div>
  );
}
```

These examples should help you integrate the feedback system into your application in various ways, depending on your specific needs and architecture.