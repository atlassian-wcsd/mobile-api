import { Feedback, FeedbackCategory, FeedbackStatus } from '../models/Feedback';
import axios from 'axios';

/**
 * Configuration for the feedback service API
 */
interface FeedbackServiceConfig {
  /** Base URL for the feedback API endpoint */
  apiBaseUrl: string;
}

/**
 * Service class for managing user feedback submissions
 */
export class FeedbackService {
  private feedbackItems: Map<string, Feedback> = new Map();
  private config: FeedbackServiceConfig;

  constructor(config?: FeedbackServiceConfig) {
    this.config = config || { apiBaseUrl: '/api' };
  }

  /**
   * Create a new feedback submission
   * @param category Category of the feedback
   * @param rating Star rating (1-5)
   * @param message The feedback message text
   * @param userId ID of the user submitting feedback
   * @param contactEmail Optional contact email for follow-up
   * @returns The created feedback object
   */
  public createFeedback(
    category: FeedbackCategory,
    rating: number,
    message: string,
    userId: string,
    contactEmail?: string
  ): Feedback {
    if (!this.validateRating(rating)) {
      throw new Error('Rating must be between 1 and 5');
    }

    if (!this.validateMessage(message)) {
      throw new Error('Message must be between 1 and 2000 characters');
    }

    if (contactEmail && !this.validateEmail(contactEmail)) {
      throw new Error('Invalid email format');
    }

    const feedback: Feedback = {
      id: this.generateFeedbackId(),
      userId,
      category,
      rating,
      message: this.sanitizeInput(message),
      contactEmail,
      createdAt: new Date(),
      status: FeedbackStatus.PENDING,
      metadata: {
        platform: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
        appVersion: '1.0.0',
        screenResolution:
          typeof window !== 'undefined'
            ? `${window.screen.width}x${window.screen.height}`
            : undefined,
      },
    };

    this.feedbackItems.set(feedback.id, feedback);
    return feedback;
  }

  /**
   * Submit feedback to the backend API
   * @param feedback The feedback object to submit
   * @returns The submitted feedback with updated status
   */
  public async submitFeedback(feedback: Feedback): Promise<Feedback> {
    try {
      await axios.post(`${this.config.apiBaseUrl}/feedback`, {
        id: feedback.id,
        userId: feedback.userId,
        category: feedback.category,
        rating: feedback.rating,
        message: feedback.message,
        contactEmail: feedback.contactEmail,
        createdAt: feedback.createdAt.toISOString(),
        metadata: feedback.metadata,
      });

      feedback.status = FeedbackStatus.SUBMITTED;
      this.feedbackItems.set(feedback.id, feedback);
      return feedback;
    } catch (error) {
      feedback.status = FeedbackStatus.FAILED;
      this.feedbackItems.set(feedback.id, feedback);
      throw error;
    }
  }

  /**
   * Create and immediately submit feedback
   * @param category Category of the feedback
   * @param rating Star rating (1-5)
   * @param message The feedback message text
   * @param userId ID of the user submitting feedback
   * @param contactEmail Optional contact email
   * @returns The submitted feedback object
   */
  public async createAndSubmitFeedback(
    category: FeedbackCategory,
    rating: number,
    message: string,
    userId: string,
    contactEmail?: string
  ): Promise<Feedback> {
    const feedback = this.createFeedback(category, rating, message, userId, contactEmail);
    return this.submitFeedback(feedback);
  }

  /**
   * Retrieve a feedback item by its ID
   * @param feedbackId The ID of the feedback to retrieve
   * @returns The feedback object if found, null otherwise
   */
  public getFeedback(feedbackId: string): Feedback | null {
    return this.feedbackItems.get(feedbackId) || null;
  }

  /**
   * Get all feedback items for a specific user
   * @param userId The ID of the user
   * @returns Array of feedback items belonging to the user
   */
  public getUserFeedback(userId: string): Feedback[] {
    return Array.from(this.feedbackItems.values()).filter(
      (feedback) => feedback.userId === userId
    );
  }

  /**
   * Validate that the rating is between 1 and 5
   * @param rating The rating value to validate
   * @returns true if valid, false otherwise
   */
  public validateRating(rating: number): boolean {
    return Number.isInteger(rating) && rating >= 1 && rating <= 5;
  }

  /**
   * Validate that the message meets length requirements
   * @param message The message to validate
   * @returns true if valid, false otherwise
   */
  public validateMessage(message: string): boolean {
    const trimmed = message.trim();
    return trimmed.length >= 1 && trimmed.length <= 2000;
  }

  /**
   * Validate email format
   * @param email The email address to validate
   * @returns true if valid email format, false otherwise
   */
  public validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Sanitize user input to prevent XSS attacks
   * @param input The input string to sanitize
   * @returns The sanitized string
   */
  public sanitizeInput(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  /**
   * Generate a unique feedback ID
   * @returns A unique string ID
   */
  private generateFeedbackId(): string {
    return 'fb_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}
