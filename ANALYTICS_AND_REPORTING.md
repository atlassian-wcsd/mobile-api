# Feedback Form Analytics & Reporting Guide

## Overview

This guide provides instructions for setting up analytics tracking and reporting for the user feedback form feature. Analytics help monitor form usage, understand user sentiment, and identify areas for improvement.

## Table of Contents

1. [Analytics Events](#analytics-events)
2. [Frontend Implementation](#frontend-implementation)
3. [Backend Implementation](#backend-implementation)
4. [Google Analytics Integration](#google-analytics-integration)
5. [Custom Analytics Service](#custom-analytics-service)
6. [Reporting Dashboard](#reporting-dashboard)
7. [Key Metrics](#key-metrics)
8. [Data Analysis](#data-analysis)

## Analytics Events

### Event Categories

#### Form View Events
- **event_name**: `feedback_form_opened`
- **triggered_by**: User clicks feedback button
- **data_points**:
  - `timestamp`: When form was opened
  - `user_id`: User who opened the form
  - `source`: Where the form was triggered from (button, menu, etc.)

#### Form Interaction Events
- **event_name**: `feedback_form_interaction`
- **triggered_by**: User interacts with form fields
- **data_points**:
  - `interaction_type`: rating, message_input, category_select, contact_input
  - `field_name`: Which field was interacted with
  - `timestamp`: When interaction occurred

#### Form Submission Events
- **event_name**: `feedback_form_submitted`
- **triggered_by**: User submits form
- **data_points**:
  - `feedback_id`: Unique ID of submitted feedback
  - `user_id`: User who submitted
  - `rating`: Rating value (1-5)
  - `category`: Feedback category
  - `message_length`: Length of message
  - `has_contact_info`: Boolean - whether contact info was provided
  - `submission_time_ms`: Time from form open to submission
  - `device_type`: Mobile, tablet, desktop
  - `timestamp`: Submission time

#### Form Error Events
- **event_name**: `feedback_form_error`
- **triggered_by**: Validation or submission error
- **data_points**:
  - `error_type`: validation_error, submission_error, network_error
  - `error_message`: Description of error
  - `user_id`: User who encountered error
  - `timestamp`: When error occurred

#### Form Abandonment Events
- **event_name**: `feedback_form_abandoned`
- **triggered_by**: User closes form without submitting
- **data_points**:
  - `user_id`: User who abandoned
  - `time_on_form_ms`: How long user had form open
  - `fields_touched`: Which fields user interacted with
  - `timestamp`: When form was closed

## Frontend Implementation

### Setup Analytics Service

Create `src/services/AnalyticsService.ts`:

```typescript
/**
 * Analytics service for tracking user interactions
 */
export class AnalyticsService {
  private static readonly ANALYTICS_ENDPOINT = '/api/analytics';

  /**
   * Track an analytics event
   */
  static trackEvent(
    eventName: string,
    eventData: Record<string, any>
  ): void {
    const enrichedData = {
      event: eventName,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      ...eventData,
    };

    // Send to custom backend
    this.sendToBackend(enrichedData);

    // Send to Google Analytics if available
    if (window.gtag) {
      window.gtag('event', eventName, eventData);
    }
  }

  /**
   * Track form view
   */
  static trackFormOpened(userId: string, source: string): void {
    this.trackEvent('feedback_form_opened', {
      user_id: userId,
      source,
    });
  }

  /**
   * Track form interaction
   */
  static trackFormInteraction(
    interactionType: string,
    fieldName: string,
    value?: any
  ): void {
    this.trackEvent('feedback_form_interaction', {
      interaction_type: interactionType,
      field_name: fieldName,
      value_type: typeof value,
    });
  }

  /**
   * Track successful form submission
   */
  static trackFormSubmitted(
    userId: string,
    feedbackData: {
      feedbackId: string;
      rating: number;
      category: string;
      messageLength: number;
      hasContactInfo: boolean;
      submissionTimeMs: number;
    }
  ): void {
    this.trackEvent('feedback_form_submitted', {
      feedback_id: feedbackData.feedbackId,
      user_id: userId,
      rating: feedbackData.rating,
      category: feedbackData.category,
      message_length: feedbackData.messageLength,
      has_contact_info: feedbackData.hasContactInfo,
      submission_time_ms: feedbackData.submissionTimeMs,
      device_type: this.detectDeviceType(),
    });
  }

  /**
   * Track form error
   */
  static trackFormError(
    errorType: string,
    errorMessage: string,
    userId?: string
  ): void {
    this.trackEvent('feedback_form_error', {
      error_type: errorType,
      error_message: errorMessage,
      user_id: userId,
    });
  }

  /**
   * Track form abandonment
   */
  static trackFormAbandoned(
    userId: string,
    timeOnFormMs: number,
    fieldsTouched: string[]
  ): void {
    this.trackEvent('feedback_form_abandoned', {
      user_id: userId,
      time_on_form_ms: timeOnFormMs,
      fields_touched: fieldsTouched,
    });
  }

  /**
   * Detect device type
   */
  private static detectDeviceType(): string {
    const userAgent = navigator.userAgent.toLowerCase();

    if (/ipad|android/.test(userAgent)) {
      return 'tablet';
    } else if (/mobile|iphone/.test(userAgent)) {
      return 'mobile';
    }
    return 'desktop';
  }

  /**
   * Send event to backend
   */
  private static sendToBackend(eventData: any): void {
    fetch(this.ANALYTICS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventData),
      // Use beacon if available for reliability
      keepalive: true,
    }).catch(error => {
      console.error('Failed to send analytics event:', error);
    });
  }
}
```

### Integrate with FeedbackForm Component

Update `src/components/FeedbackForm.tsx`:

```typescript
import { AnalyticsService } from '../services/AnalyticsService';

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  userId,
  onSubmitSuccess,
  onSubmitError,
  onClose,
}) => {
  const [formOpenTime] = useState<number>(Date.now());
  const [fieldsTouched, setFieldsTouched] = useState<Set<string>>(new Set());

  // Track form opened
  useEffect(() => {
    AnalyticsService.trackFormOpened(userId, 'feedback_button');
  }, [userId]);

  // Track field interactions
  const handleRatingChange = (value: number) => {
    setRating(value);
    setFieldsTouched(prev => new Set(prev).add('rating'));
    AnalyticsService.trackFormInteraction('rating_selected', 'rating', value);
  };

  const handleMessageChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newMessage = event.target.value;
    setMessage(newMessage);
    if (!fieldsTouched.has('message')) {
      setFieldsTouched(prev => new Set(prev).add('message'));
    }
    AnalyticsService.trackFormInteraction('text_input', 'message', newMessage.length);
  };

  const handleCategoryChange = (value: string) => {
    setCategory(value as any);
    setFieldsTouched(prev => new Set(prev).add('category'));
    AnalyticsService.trackFormInteraction('category_selected', 'category', value);
  };

  const handleContactChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setContactInfo(value);
    if (!fieldsTouched.has('contactInfo')) {
      setFieldsTouched(prev => new Set(prev).add('contactInfo'));
    }
    AnalyticsService.trackFormInteraction('contact_input', 'contactInfo');
  };

  // Track successful submission
  const handleSubmitSuccess = (feedbackId: string) => {
    const submissionTimeMs = Date.now() - formOpenTime;

    AnalyticsService.trackFormSubmitted(userId, {
      feedbackId,
      rating,
      category,
      messageLength: message.length,
      hasContactInfo: !!contactInfo,
      submissionTimeMs,
    });

    if (onSubmitSuccess) {
      onSubmitSuccess(feedbackId);
    }
  };

  // Track errors
  const handleSubmitError = (error: string) => {
    AnalyticsService.trackFormError('submission_error', error, userId);
    if (onSubmitError) {
      onSubmitError(error);
    }
  };

  // Track abandonment
  const handleClose = () => {
    const timeOnFormMs = Date.now() - formOpenTime;

    AnalyticsService.trackFormAbandoned(
      userId,
      timeOnFormMs,
      Array.from(fieldsTouched)
    );

    if (onClose) {
      onClose();
    }
  };

  // ... rest of component
};
```

## Backend Implementation

### Analytics Handler

Create `submitImage/analytics/analytics.go`:

```go
package analytics

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// AnalyticsEvent represents a tracked analytics event
type AnalyticsEvent struct {
	Event        string                 `json:"event"`
	UserID       string                 `json:"user_id,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	Data         map[string]interface{} `json:"data,omitempty"`
	UserAgent    string                 `json:"userAgent,omitempty"`
}

// AnalyticsStore stores analytics events
type AnalyticsStore interface {
	StoreEvent(event AnalyticsEvent) error
	GetEvents(filter map[string]interface{}) ([]AnalyticsEvent, error)
	GetStatistics(dateRange map[string]time.Time) (map[string]interface{}, error)
}

// AnalyticsHandler handles analytics endpoints
type AnalyticsHandler struct {
	store AnalyticsStore
}

// NewAnalyticsHandler creates new analytics handler
func NewAnalyticsHandler(store AnalyticsStore) *AnalyticsHandler {
	return &AnalyticsHandler{store: store}
}

// TrackEventHandler handles POST /api/analytics
func (h *AnalyticsHandler) TrackEventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event AnalyticsEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set timestamp if not provided
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Store event
	if err := h.store.StoreEvent(event); err != nil {
		log.Printf("Failed to store analytics event: %v", err)
		http.Error(w, "Failed to store event", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// GetAnalyticsHandler handles GET /api/admin/analytics
func (h *AnalyticsHandler) GetAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters for filtering
	filter := make(map[string]interface{})
	if eventType := r.URL.Query().Get("event"); eventType != "" {
		filter["event"] = eventType
	}

	events, err := h.store.GetEvents(filter)
	if err != nil {
		http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(events)
}

// GetStatisticsHandler handles GET /api/admin/analytics/statistics
func (h *AnalyticsHandler) GetStatisticsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get date range from query parameters
	dateRange := make(map[string]time.Time)
	// Parse dates if provided

	stats, err := h.store.GetStatistics(dateRange)
	if err != nil {
		http.Error(w, "Failed to retrieve statistics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
```

## Google Analytics Integration

### Setup GTM/GA

Add to your HTML head:

```html
<!-- Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_MEASUREMENT_ID');
</script>
```

### Custom Events in GA

```typescript
// Track events in Google Analytics
window.gtag?.('event', 'feedback_form_submitted', {
  'feedback_id': 'fb_123',
  'rating': 5,
  'category': 'feature-request',
  'message_length': 250
});
```

## Custom Analytics Service

### In-Memory Storage

```go
package analytics

import (
	"sync"
	"time"
)

type InMemoryAnalyticsStore struct {
	mu     sync.RWMutex
	events []AnalyticsEvent
}

func NewInMemoryAnalyticsStore() *InMemoryAnalyticsStore {
	return &InMemoryAnalyticsStore{
		events: make([]AnalyticsEvent, 0),
	}
}

func (s *InMemoryAnalyticsStore) StoreEvent(event AnalyticsEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	return nil
}

func (s *InMemoryAnalyticsStore) GetEvents(filter map[string]interface{}) ([]AnalyticsEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []AnalyticsEvent

	for _, event := range s.events {
		// Apply filters
		if eventType, ok := filter["event"].(string); ok && event.Event != eventType {
			continue
		}

		results = append(results, event)
	}

	return results, nil
}

func (s *InMemoryAnalyticsStore) GetStatistics(dateRange map[string]time.Time) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"total_events":   0,
		"events_by_type": make(map[string]int),
	}

	for _, event := range s.events {
		totalEvents := stats["total_events"].(int)
		stats["total_events"] = totalEvents + 1

		eventsByType := stats["events_by_type"].(map[string]int)
		eventsByType[event.Event]++
	}

	return stats, nil
}
```

## Reporting Dashboard

### Admin Dashboard Component

```typescript
// src/pages/AnalyticsDashboard.tsx

import React, { useEffect, useState } from 'react';
import { AnalyticsService } from '../services/AnalyticsService';

export function AnalyticsDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    const loadAnalytics = async () => {
      // Fetch analytics data from backend
      const response = await fetch('/api/admin/analytics/statistics');
      const data = await response.json();
      setStats(data);

      const eventsResponse = await fetch('/api/admin/analytics');
      const eventsData = await eventsResponse.json();
      setEvents(eventsData);
    };

    loadAnalytics();
  }, []);

  return (
    <div className="analytics-dashboard">
      <h1>Feedback Form Analytics</h1>

      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <h3>Total Events</h3>
            <p className="stat-value">{stats.total_events}</p>
          </div>

          <div className="stat-card">
            <h3>Forms Opened</h3>
            <p className="stat-value">
              {stats.events_by_type?.feedback_form_opened || 0}
            </p>
          </div>

          <div className="stat-card">
            <h3>Forms Submitted</h3>
            <p className="stat-value">
              {stats.events_by_type?.feedback_form_submitted || 0}
            </p>
          </div>

          <div className="stat-card">
            <h3>Submission Rate</h3>
            <p className="stat-value">
              {stats.total_events > 0
                ? Math.round(
                    ((stats.events_by_type?.feedback_form_submitted || 0) /
                      stats.total_events) *
                      100
                  ) + '%'
                : 'N/A'}
            </p>
          </div>
        </div>
      )}

      <div className="events-list">
        <h2>Recent Events</h2>
        <table>
          <thead>
            <tr>
              <th>Event Type</th>
              <th>User ID</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, 20).map((event, idx) => (
              <tr key={idx}>
                <td>{event.event}</td>
                <td>{event.user_id || '-'}</td>
                <td>{new Date(event.timestamp).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
```

## Key Metrics

### Form Engagement
- Form impressions (button views)
- Form open rate
- Form interaction rate
- Form submission rate

### User Experience
- Average time to submit
- Abandonment rate
- Fields most commonly filled
- Common error types

### Feedback Quality
- Average rating
- Rating distribution
- Most common categories
- Message length distribution

### User Segments
- Submissions per user
- Repeat submitters
- Device type breakdown
- Time of day distribution

## Data Analysis

### Weekly Report Template

```sql
-- Weekly feedback metrics
SELECT
  DATE_TRUNC('week', timestamp) as week,
  COUNT(*) as total_events,
  COUNT(CASE WHEN event = 'feedback_form_submitted' THEN 1 END) as submissions,
  ROUND(
    100.0 * COUNT(CASE WHEN event = 'feedback_form_submitted' THEN 1 END) /
    COUNT(*), 2
  ) as submission_rate,
  COUNT(DISTINCT user_id) as unique_users
FROM analytics_events
WHERE event IN ('feedback_form_opened', 'feedback_form_submitted')
GROUP BY week
ORDER BY week DESC;
```

### Rating Distribution

```sql
SELECT
  data->>'rating' as rating,
  COUNT(*) as count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) as percentage
FROM analytics_events
WHERE event = 'feedback_form_submitted'
GROUP BY data->>'rating'
ORDER BY rating DESC;
```

---

**Last Updated:** 2025-01-15
**Version:** 1.0.0
