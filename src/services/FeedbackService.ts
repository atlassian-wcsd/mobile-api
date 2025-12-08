import { Feedback, FeedbackBuilder } from '../models/Feedback';

/**
 * Service class for managing user feedback
 */
export class FeedbackService {
  private feedbacks: Map<string, Feedback> = new Map();

  /**
   * Submit new feedback
   * @param userId User ID submitting the feedback
   * @param message Feedback message text
   * @param rating Rating on scale of 1-5
   * @param contactInfo Optional contact information
   * @param category Optional feedback category
   * @returns The created feedback object
   */
  public submitFeedback(
    userId: string,
    message: string,
    rating: number,
    contactInfo?: string,
    category?: 'bug' | 'feature-request' | 'general' | 'other'
  ): Feedback {
    const feedback = new FeedbackBuilder()
      .setId(this.generateFeedbackId())
      .setUserId(userId)
      .setMessage(message)
      .setRating(rating)
      .setContactInfo(contactInfo)
      .setCategory(category)
      .setMetadata({
        userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
        device: this.detectDevice()
      })
      .build();

    this.feedbacks.set(feedback.id, feedback);
    return feedback;
  }

  /**
   * Retrieve feedback by ID
   * @param feedbackId The ID of the feedback
   * @returns The feedback object if found, null otherwise
   */
  public getFeedback(feedbackId: string): Feedback | null {
    return this.feedbacks.get(feedbackId) || null;
  }

  /**
   * Get all feedback for a specific user
   * @param userId The ID of the user
   * @returns Array of feedback submitted by the user
   */
  public getUserFeedback(userId: string): Feedback[] {
    return Array.from(this.feedbacks.values())
      .filter(feedback => feedback.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Get all feedback (admin/support use)
   * @param status Optional filter by status
   * @returns Array of all feedback
   */
  public getAllFeedback(status?: string): Feedback[] {
    let results = Array.from(this.feedbacks.values());
    
    if (status) {
      results = results.filter(feedback => feedback.status === status);
    }

    return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Get feedback by category
   * @param category The feedback category
   * @returns Array of feedback in that category
   */
  public getFeedbackByCategory(category: string): Feedback[] {
    return Array.from(this.feedbacks.values())
      .filter(feedback => feedback.category === category)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Update feedback status
   * @param feedbackId The ID of the feedback
   * @param status New status
   * @param internalNotes Optional internal notes
   * @returns The updated feedback if found, null otherwise
   */
  public updateFeedbackStatus(
    feedbackId: string,
    status: 'new' | 'reviewed' | 'resolved' | 'archived',
    internalNotes?: string
  ): Feedback | null {
    const feedback = this.feedbacks.get(feedbackId);
    if (!feedback) return null;

    feedback.status = status;
    if (internalNotes) {
      feedback.internalNotes = internalNotes;
    }

    this.feedbacks.set(feedbackId, feedback);
    return feedback;
  }

  /**
   * Validate feedback submission
   * @param message Feedback message
   * @param rating Rating value
   * @returns Object containing validation result and error messages
   */
  public validateFeedback(message: string, rating: number): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!message || message.trim().length === 0) {
      errors.push('Feedback message is required');
    }

    if (message && message.trim().length > 5000) {
      errors.push('Feedback message cannot exceed 5000 characters');
    }

    if (!rating || rating < 1 || rating > 5 || !Number.isInteger(rating)) {
      errors.push('Rating must be an integer between 1 and 5');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Delete feedback (admin/support use)
   * @param feedbackId The ID of the feedback to delete
   * @returns true if deleted, false if not found
   */
  public deleteFeedback(feedbackId: string): boolean {
    return this.feedbacks.delete(feedbackId);
  }

  /**
   * Get feedback statistics
   * @returns Object containing feedback statistics
   */
  public getStatistics(): {
    totalFeedback: number;
    averageRating: number;
    feedbackByCategory: Record<string, number>;
    feedbackByStatus: Record<string, number>;
  } {
    const allFeedback = Array.from(this.feedbacks.values());

    const categoryCount: Record<string, number> = {};
    const statusCount: Record<string, number> = {};
    let ratingSum = 0;

    allFeedback.forEach(feedback => {
      ratingSum += feedback.rating;
      categoryCount[feedback.category || 'general'] = (categoryCount[feedback.category || 'general'] || 0) + 1;
      statusCount[feedback.status || 'new'] = (statusCount[feedback.status || 'new'] || 0) + 1;
    });

    return {
      totalFeedback: allFeedback.length,
      averageRating: allFeedback.length > 0 ? ratingSum / allFeedback.length : 0,
      feedbackByCategory: categoryCount,
      feedbackByStatus: statusCount
    };
  }

  /**
   * Detect device type
   * @returns Device type string
   */
  private detectDevice(): string {
    if (typeof navigator === 'undefined') return 'unknown';

    const userAgent = navigator.userAgent.toLowerCase();

    if (/mobile|android|iphone|ipad|tablet/.test(userAgent)) {
      if (/ipad|android/.test(userAgent)) return 'tablet';
      return 'mobile';
    }
    return 'desktop';
  }

  /**
   * Generate a unique feedback ID
   * @returns A unique string ID
   */
  private generateFeedbackId(): string {
    return 'fb_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}
