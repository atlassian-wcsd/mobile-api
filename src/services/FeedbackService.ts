import { 
  Feedback, 
  FeedbackSubmissionRequest, 
  FeedbackSubmissionResponse,
  FeedbackBuilder,
  FeedbackType,
  FeedbackStatus 
} from '../models/Feedback';

/**
 * Service for handling feedback operations
 */
export class FeedbackService {
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com/v1';
  }

  /**
   * Submit user feedback
   */
  async submitFeedback(feedbackRequest: FeedbackSubmissionRequest): Promise<FeedbackSubmissionResponse> {
    try {
      // Validate the request
      this.validateFeedbackRequest(feedbackRequest);

      // Add metadata
      const enrichedRequest = {
        ...feedbackRequest,
        metadata: {
          ...feedbackRequest.metadata,
          appVersion: process.env.REACT_APP_VERSION || '1.0.0',
          screenResolution: `${window.screen.width}x${window.screen.height}`,
          timestamp: new Date().toISOString(),
          url: window.location.href,
          ...feedbackRequest.metadata
        }
      };

      const response = await this.makeRequest('/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(enrichedRequest)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return {
        success: true,
        feedbackId: data.feedbackId,
        message: data.message || 'Feedback submitted successfully'
      };

    } catch (error) {
      console.error('Failed to submit feedback:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to submit feedback'
      };
    }
  }

  /**
   * Get feedback by ID (for admin/support use)
   */
  async getFeedback(feedbackId: string, authToken?: string): Promise<Feedback | null> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response = await this.makeRequest(`/feedback/${feedbackId}`, {
        method: 'GET',
        headers
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return this.mapResponseToFeedback(data);

    } catch (error) {
      console.error('Failed to get feedback:', error);
      return null;
    }
  }

  /**
   * Get user's feedback history
   */
  async getUserFeedback(userId: string, authToken: string): Promise<Feedback[]> {
    try {
      const response = await this.makeRequest(`/feedback/user/${userId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data.feedback?.map((item: any) => this.mapResponseToFeedback(item)) || [];

    } catch (error) {
      console.error('Failed to get user feedback:', error);
      return [];
    }
  }

  /**
   * Validate feedback request
   */
  private validateFeedbackRequest(request: FeedbackSubmissionRequest): void {
    if (!request.type || !Object.values(FeedbackType).includes(request.type)) {
      throw new Error('Valid feedback type is required');
    }

    if (!request.rating || request.rating < 1 || request.rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }

    if (!request.subject || request.subject.trim().length === 0) {
      throw new Error('Subject is required');
    }

    if (!request.message || request.message.trim().length === 0) {
      throw new Error('Message is required');
    }

    if (request.subject.length > 200) {
      throw new Error('Subject must be 200 characters or less');
    }

    if (request.message.length > 2000) {
      throw new Error('Message must be 2000 characters or less');
    }

    if (request.email && !this.isValidEmail(request.email)) {
      throw new Error('Invalid email format');
    }
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Map API response to Feedback object
   */
  private mapResponseToFeedback(data: any): Feedback {
    return new FeedbackBuilder()
      .setId(data.id)
      .setUserId(data.userId)
      .setEmail(data.email)
      .setName(data.name)
      .setType(data.type)
      .setRating(data.rating)
      .setSubject(data.subject)
      .setMessage(data.message)
      .setPage(data.page)
      .setUserAgent(data.userAgent)
      .setStatus(data.status || FeedbackStatus.NEW)
      .setMetadata(data.metadata)
      .build();
  }

  /**
   * Make HTTP request with error handling
   */
  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultOptions: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
      },
      ...options
    };

    try {
      const response = await fetch(url, defaultOptions);
      return response;
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network error: Please check your internet connection');
      }
      throw error;
    }
  }
}

/**
 * Utility functions for feedback
 */
export class FeedbackUtils {
  /**
   * Get user-friendly feedback type label
   */
  static getFeedbackTypeLabel(type: FeedbackType): string {
    const labels: Record<FeedbackType, string> = {
      [FeedbackType.BUG_REPORT]: 'Bug Report',
      [FeedbackType.FEATURE_REQUEST]: 'Feature Request',
      [FeedbackType.GENERAL_FEEDBACK]: 'General Feedback',
      [FeedbackType.USABILITY_ISSUE]: 'Usability Issue',
      [FeedbackType.PERFORMANCE_ISSUE]: 'Performance Issue',
      [FeedbackType.OTHER]: 'Other'
    };
    return labels[type] || 'Unknown';
  }

  /**
   * Get rating display (stars)
   */
  static getRatingDisplay(rating: number): string {
    return '★'.repeat(rating) + '☆'.repeat(5 - rating);
  }

  /**
   * Get status color for UI
   */
  static getStatusColor(status: FeedbackStatus): string {
    const colors: Record<FeedbackStatus, string> = {
      [FeedbackStatus.NEW]: '#007bff',
      [FeedbackStatus.IN_REVIEW]: '#ffc107',
      [FeedbackStatus.RESOLVED]: '#28a745',
      [FeedbackStatus.CLOSED]: '#6c757d'
    };
    return colors[status] || '#6c757d';
  }
}