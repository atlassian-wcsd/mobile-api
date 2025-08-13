import { Feedback, FeedbackSubmissionRequest, FeedbackSubmissionResponse } from '../models/Feedback';

export class FeedbackService {
  private readonly baseUrl: string;

  constructor() {
    this.baseUrl = process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com/v1';
  }

  /**
   * Submit feedback to the backend
   */
  async submitFeedback(feedbackRequest: FeedbackSubmissionRequest): Promise<FeedbackSubmissionResponse> {
    try {
      const response = await this.makeRequest('/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          rating: feedbackRequest.rating,
          category: feedbackRequest.category,
          subject: feedbackRequest.subject,
          message: feedbackRequest.message,
          email: feedbackRequest.email,
          deviceInfo: this.getDeviceInfo(),
          timestamp: new Date().toISOString()
        })
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
   * Get user's feedback history (if authenticated)
   */
  async getFeedbackHistory(authToken?: string): Promise<Feedback[]> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response = await this.makeRequest('/feedback/history', {
        method: 'GET',
        headers
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data.feedback || [];
    } catch (error) {
      console.error('Failed to get feedback history:', error);
      return [];
    }
  }

  /**
   * Upload attachment for feedback
   */
  async uploadAttachment(file: File): Promise<string> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await this.makeRequest('/feedback/upload', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data.url;
    } catch (error) {
      console.error('Failed to upload attachment:', error);
      throw error;
    }
  }

  /**
   * Get feedback categories for the dropdown
   */
  getFeedbackCategories(): Array<{ value: string; label: string }> {
    return [
      { value: 'bug_report', label: 'Bug Report' },
      { value: 'feature_request', label: 'Feature Request' },
      { value: 'general_feedback', label: 'General Feedback' },
      { value: 'support_request', label: 'Support Request' },
      { value: 'performance_issue', label: 'Performance Issue' },
      { value: 'ui_ux_feedback', label: 'UI/UX Feedback' }
    ];
  }

  /**
   * Collect device information for debugging purposes
   */
  private getDeviceInfo() {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      timestamp: new Date()
    };
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

export class FeedbackServiceUtils {
  /**
   * Format feedback for display
   */
  static formatFeedback(feedback: Feedback): string {
    const date = feedback.createdAt.toLocaleDateString();
    const time = feedback.createdAt.toLocaleTimeString();
    return `${feedback.subject} - ${date} ${time}`;
  }

  /**
   * Get rating display (stars)
   */
  static getRatingDisplay(rating: number): string {
    return '★'.repeat(rating) + '☆'.repeat(5 - rating);
  }

  /**
   * Get category display name
   */
  static getCategoryDisplayName(category: string): string {
    const categoryMap: Record<string, string> = {
      'bug_report': 'Bug Report',
      'feature_request': 'Feature Request',
      'general_feedback': 'General Feedback',
      'support_request': 'Support Request',
      'performance_issue': 'Performance Issue',
      'ui_ux_feedback': 'UI/UX Feedback'
    };
    return categoryMap[category] || category;
  }

  /**
   * Validate file for attachment
   */
  static validateAttachment(file: File): string | null {
    const maxSize = 5 * 1024 * 1024; // 5MB
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'];

    if (file.size > maxSize) {
      return 'File size must be less than 5MB';
    }

    if (!allowedTypes.includes(file.type)) {
      return 'File type not supported. Please use JPEG, PNG, GIF, TXT, or PDF files.';
    }

    return null;
  }
}