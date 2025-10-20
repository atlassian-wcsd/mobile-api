/**
 * Interface representing user feedback
 */
export interface Feedback {
  /**
   * Unique identifier for the feedback
   */
  id: string;

  /**
   * User ID of the person who submitted the feedback
   */
  userId?: string;

  /**
   * User's email address (optional, for anonymous feedback)
   */
  email?: string;

  /**
   * User's name (optional)
   */
  name?: string;

  /**
   * Type/category of feedback
   */
  type: FeedbackType;

  /**
   * Rating from 1-5 stars
   */
  rating: number;

  /**
   * Subject/title of the feedback
   */
  subject: string;

  /**
   * Detailed feedback message
   */
  message: string;

  /**
   * Current page/section where feedback was submitted
   */
  page?: string;

  /**
   * Browser/device information
   */
  userAgent?: string;

  /**
   * Timestamp when the feedback was created
   */
  createdAt: Date;

  /**
   * Status of the feedback
   */
  status: FeedbackStatus;

  /**
   * Additional metadata
   */
  metadata?: {
    /**
     * App version when feedback was submitted
     */
    appVersion?: string;
    
    /**
     * Screen resolution
     */
    screenResolution?: string;
    
    /**
     * Any additional context
     */
    context?: Record<string, any>;
  };
}

/**
 * Types of feedback
 */
export enum FeedbackType {
  BUG_REPORT = 'bug_report',
  FEATURE_REQUEST = 'feature_request',
  GENERAL_FEEDBACK = 'general_feedback',
  USABILITY_ISSUE = 'usability_issue',
  PERFORMANCE_ISSUE = 'performance_issue',
  OTHER = 'other'
}

/**
 * Status of feedback
 */
export enum FeedbackStatus {
  NEW = 'new',
  IN_REVIEW = 'in_review',
  RESOLVED = 'resolved',
  CLOSED = 'closed'
}

/**
 * Request interface for submitting feedback
 */
export interface FeedbackSubmissionRequest {
  email?: string;
  name?: string;
  type: FeedbackType;
  rating: number;
  subject: string;
  message: string;
  page?: string;
  metadata?: {
    appVersion?: string;
    screenResolution?: string;
    context?: Record<string, any>;
  };
}

/**
 * Response interface for feedback submission
 */
export interface FeedbackSubmissionResponse {
  success: boolean;
  feedbackId?: string;
  error?: string;
  message?: string;
}

/**
 * Builder class for creating Feedback objects
 */
export class FeedbackBuilder {
  private feedback: Partial<Feedback> = {};

  setId(id: string): FeedbackBuilder {
    this.feedback.id = id;
    return this;
  }

  setUserId(userId: string): FeedbackBuilder {
    this.feedback.userId = userId;
    return this;
  }

  setEmail(email: string): FeedbackBuilder {
    this.feedback.email = email;
    return this;
  }

  setName(name: string): FeedbackBuilder {
    this.feedback.name = name;
    return this;
  }

  setType(type: FeedbackType): FeedbackBuilder {
    this.feedback.type = type;
    return this;
  }

  setRating(rating: number): FeedbackBuilder {
    if (rating < 1 || rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }
    this.feedback.rating = rating;
    return this;
  }

  setSubject(subject: string): FeedbackBuilder {
    this.feedback.subject = subject;
    return this;
  }

  setMessage(message: string): FeedbackBuilder {
    this.feedback.message = message;
    return this;
  }

  setPage(page: string): FeedbackBuilder {
    this.feedback.page = page;
    return this;
  }

  setUserAgent(userAgent: string): FeedbackBuilder {
    this.feedback.userAgent = userAgent;
    return this;
  }

  setStatus(status: FeedbackStatus): FeedbackBuilder {
    this.feedback.status = status;
    return this;
  }

  setMetadata(metadata: Feedback['metadata']): FeedbackBuilder {
    this.feedback.metadata = metadata;
    return this;
  }

  build(): Feedback {
    const now = new Date();
    
    if (!this.feedback.type || !this.feedback.rating || !this.feedback.subject || !this.feedback.message) {
      throw new Error('Feedback must have type, rating, subject, and message');
    }

    return {
      id: this.feedback.id || crypto.randomUUID(),
      userId: this.feedback.userId,
      email: this.feedback.email,
      name: this.feedback.name,
      type: this.feedback.type,
      rating: this.feedback.rating,
      subject: this.feedback.subject,
      message: this.feedback.message,
      page: this.feedback.page || window.location.pathname,
      userAgent: this.feedback.userAgent || navigator.userAgent,
      createdAt: now,
      status: this.feedback.status || FeedbackStatus.NEW,
      metadata: this.feedback.metadata
    };
  }
}