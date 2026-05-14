/**
 * Enum representing feedback categories
 */
export enum FeedbackCategory {
  BUG = 'bug',
  FEATURE_REQUEST = 'feature_request',
  IMPROVEMENT = 'improvement',
  GENERAL = 'general',
}

/**
 * Enum representing feedback submission status
 */
export enum FeedbackStatus {
  PENDING = 'pending',
  SUBMITTED = 'submitted',
  FAILED = 'failed',
}

/**
 * Interface representing a user feedback submission
 */
export interface Feedback {
  /**
   * Unique identifier for the feedback
   */
  id: string;

  /**
   * User ID of the person who submitted the feedback
   */
  userId: string;

  /**
   * Category of the feedback
   */
  category: FeedbackCategory;

  /**
   * Star rating from 1 to 5
   */
  rating: number;

  /**
   * The feedback message text
   */
  message: string;

  /**
   * Optional contact email for follow-up
   */
  contactEmail?: string;

  /**
   * Timestamp when the feedback was created
   */
  createdAt: Date;

  /**
   * Current submission status
   */
  status: FeedbackStatus;

  /**
   * Metadata about the feedback submission
   */
  metadata: {
    /**
     * Browser/platform information
     */
    platform: string;

    /**
     * App version at time of submission
     */
    appVersion: string;

    /**
     * Screen resolution at time of submission
     */
    screenResolution?: string;
  };
}
