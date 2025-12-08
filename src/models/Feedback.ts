/**
 * Interface representing user feedback
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
   * Main feedback text/message
   */
  message: string;

  /**
   * Rating provided by user (1-5 scale)
   */
  rating: number;

  /**
   * Optional contact information (email, phone)
   */
  contactInfo?: string;

  /**
   * Optional category for the feedback (bug, feature request, general comment)
   */
  category?: 'bug' | 'feature-request' | 'general' | 'other';

  /**
   * Timestamp when feedback was created
   */
  createdAt: Date;

  /**
   * Device and platform information
   */
  metadata: {
    /**
     * User agent string
     */
    userAgent?: string;
    /**
     * App version
     */
    appVersion?: string;
    /**
     * Device type
     */
    device?: string;
  };

  /**
   * Status of the feedback (new, reviewed, resolved, archived)
   */
  status?: 'new' | 'reviewed' | 'resolved' | 'archived';

  /**
   * Optional internal notes about the feedback
   */
  internalNotes?: string;
}

/**
 * Request payload for submitting feedback
 */
export interface FeedbackSubmissionRequest {
  message: string;
  rating: number;
  contactInfo?: string;
  category?: 'bug' | 'feature-request' | 'general' | 'other';
}

/**
 * Response from feedback submission
 */
export interface FeedbackSubmissionResponse {
  success: boolean;
  feedbackId?: string;
  message: string;
  error?: string;
}

/**
 * Builder class for constructing Feedback objects
 */
export class FeedbackBuilder {
  private feedback: Partial<Feedback> = {
    metadata: {}
  };

  setId(id: string): FeedbackBuilder {
    this.feedback.id = id;
    return this;
  }

  setUserId(userId: string): FeedbackBuilder {
    this.feedback.userId = userId;
    return this;
  }

  setMessage(message: string): FeedbackBuilder {
    this.feedback.message = message;
    return this;
  }

  setRating(rating: number): FeedbackBuilder {
    if (rating < 1 || rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }
    this.feedback.rating = rating;
    return this;
  }

  setContactInfo(contactInfo?: string): FeedbackBuilder {
    this.feedback.contactInfo = contactInfo;
    return this;
  }

  setCategory(category?: 'bug' | 'feature-request' | 'general' | 'other'): FeedbackBuilder {
    this.feedback.category = category;
    return this;
  }

  setMetadata(metadata: Partial<Feedback['metadata']>): FeedbackBuilder {
    this.feedback.metadata = { ...this.feedback.metadata, ...metadata };
    return this;
  }

  setStatus(status?: 'new' | 'reviewed' | 'resolved' | 'archived'): FeedbackBuilder {
    this.feedback.status = status;
    return this;
  }

  setInternalNotes(notes?: string): FeedbackBuilder {
    this.feedback.internalNotes = notes;
    return this;
  }

  build(): Feedback {
    if (!this.feedback.id || !this.feedback.userId || !this.feedback.message || this.feedback.rating === undefined) {
      throw new Error('Feedback must have id, userId, message, and rating');
    }

    return {
      id: this.feedback.id,
      userId: this.feedback.userId,
      message: this.feedback.message,
      rating: this.feedback.rating,
      contactInfo: this.feedback.contactInfo,
      category: this.feedback.category || 'general',
      createdAt: new Date(),
      metadata: this.feedback.metadata || {},
      status: this.feedback.status || 'new',
      internalNotes: this.feedback.internalNotes
    };
  }
}
