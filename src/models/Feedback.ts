/**
 * Interface representing user feedback entry
 */
export interface Feedback {
  /**
   * Unique identifier for the feedback
   */
  id: string;

  /**
   * User ID who submitted the feedback
   */
  userId: string;

  /**
   * Type of feedback (bug, feature, improvement, general)
   */
  feedbackType: 'bug' | 'feature' | 'improvement' | 'general';

  /**
   * Rating score (1-5 stars)
   */
  rating?: number;

  /**
   * Title/Subject of the feedback
   */
  title: string;

  /**
   * Detailed feedback message
   */
  message: string;

  /**
   * Category/Feature area (signature, login, general)
   */
  category: string;

  /**
   * Current page/screen where feedback was submitted
   */
  pageContext?: string;

  /**
   * User agent information
   */
  userAgent?: string;

  /**
   * Device information
   */
  deviceInfo?: {
    platform: string;
    browser: string;
    screenResolution: string;
    isMobile: boolean;
  };

  /**
   * Timestamp when feedback was submitted
   */
  createdAt: Date;

  /**
   * Status of the feedback (pending, reviewed, resolved, closed)
   */
  status: 'pending' | 'reviewed' | 'resolved' | 'closed';

  /**
   * Optional email for follow-up
   */
  email?: string;

  /**
   * Whether user wants to be contacted
   */
  allowContact: boolean;

  /**
   * Optional screenshot or attachment IDs
   */
  attachmentIds?: string[];

  /**
   * Admin notes (internal use)
   */
  adminNotes?: string;

  /**
   * Last updated timestamp
   */
  updatedAt?: Date;
}

/**
 * Request payload for submitting feedback
 */
export interface FeedbackSubmitRequest {
  feedbackType: 'bug' | 'feature' | 'improvement' | 'general';
  rating?: number;
  title: string;
  message: string;
  category: string;
  pageContext?: string;
  email?: string;
  allowContact: boolean;
  attachmentIds?: string[];
}

/**
 * Response after submitting feedback
 */
export interface FeedbackSubmitResponse {
  success: boolean;
  feedbackId?: string;
  message: string;
  error?: string;
}

/**
 * Interface for user metrics/analytics
 */
export interface UserMetric {
  /**
   * Unique identifier for the metric entry
   */
  id: string;

  /**
   * User ID associated with the metric
   */
  userId: string;

  /**
   * Type of event being tracked
   */
  eventType: string;

  /**
   * Event name (e.g., 'signature_created', 'login_success', 'page_view')
   */
  eventName: string;

  /**
   * Additional event properties
   */
  properties?: Record<string, any>;

  /**
   * Session ID to group related events
   */
  sessionId?: string;

  /**
   * Page/screen where event occurred
   */
  page?: string;

  /**
   * Duration in milliseconds (for timing events)
   */
  duration?: number;

  /**
   * Timestamp when event occurred
   */
  timestamp: Date;

  /**
   * Device and browser information
   */
  context?: {
    userAgent: string;
    platform: string;
    browser: string;
    screenResolution: string;
    viewport: string;
    isMobile: boolean;
    isTablet: boolean;
  };

  /**
   * Geographic information (if available)
   */
  geo?: {
    country?: string;
    region?: string;
    city?: string;
  };
}

/**
 * Request for tracking a metric/event
 */
export interface MetricTrackRequest {
  eventType: string;
  eventName: string;
  properties?: Record<string, any>;
  sessionId?: string;
  page?: string;
  duration?: number;
}

/**
 * Response after tracking a metric
 */
export interface MetricTrackResponse {
  success: boolean;
  metricId?: string;
  message: string;
  error?: string;
}

/**
 * Aggregated metrics for analytics dashboard
 */
export interface MetricsSummary {
  totalEvents: number;
  uniqueUsers: number;
  eventsByType: Record<string, number>;
  averageSessionDuration: number;
  topPages: Array<{ page: string; views: number }>;
  deviceBreakdown: {
    mobile: number;
    tablet: number;
    desktop: number;
  };
  timeRange: {
    start: Date;
    end: Date;
  };
}
