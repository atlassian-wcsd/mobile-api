import axios, { AxiosResponse } from 'axios';
import { FeedbackRequest, FeedbackResponse, Feedback } from '../models/Feedback';

export class FeedbackService {
  private baseURL: string;
  private timeout: number;

  constructor() {
    this.baseURL = process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com';
    this.timeout = 10000; // 10 seconds
  }

  /**
   * Submit feedback to the backend
   */
  async submitFeedback(feedbackRequest: FeedbackRequest, authToken?: string): Promise<FeedbackResponse> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      // Add authorization header if user is authenticated
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response: AxiosResponse<FeedbackResponse> = await axios.post(
        `${this.baseURL}/feedback/submit`,
        feedbackRequest,
        {
          headers,
          timeout: this.timeout,
        }
      );

      return response.data;
    } catch (error) {
      console.error('Failed to submit feedback:', error);
      
      if (axios.isAxiosError(error)) {
        if (error.response) {
          // Server responded with error status
          return {
            success: false,
            message: 'Failed to submit feedback',
            error: error.response.data?.error || error.response.statusText
          };
        } else if (error.request) {
          // Network error
          return {
            success: false,
            message: 'Network error - please check your connection',
            error: 'Network error'
          };
        }
      }

      return {
        success: false,
        message: 'An unexpected error occurred',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get feedback history for authenticated user
   */
  async getFeedbackHistory(authToken: string, limit: number = 10): Promise<Feedback[]> {
    try {
      const response: AxiosResponse<{ feedbacks: Feedback[] }> = await axios.get(
        `${this.baseURL}/feedback/history`,
        {
          headers: {
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json',
          },
          params: { limit },
          timeout: this.timeout,
        }
      );

      return response.data.feedbacks || [];
    } catch (error) {
      console.error('Failed to get feedback history:', error);
      return [];
    }
  }

  /**
   * Get feedback status by ID
   */
  async getFeedbackStatus(feedbackId: string, authToken?: string): Promise<Feedback | null> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response: AxiosResponse<{ feedback: Feedback }> = await axios.get(
        `${this.baseURL}/feedback/${feedbackId}`,
        {
          headers,
          timeout: this.timeout,
        }
      );

      return response.data.feedback;
    } catch (error) {
      console.error('Failed to get feedback status:', error);
      return null;
    }
  }

  /**
   * Upload attachment for feedback
   */
  async uploadAttachment(file: File, authToken?: string): Promise<string | null> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const headers: Record<string, string> = {};

      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response: AxiosResponse<{ url: string }> = await axios.post(
        `${this.baseURL}/feedback/upload`,
        formData,
        {
          headers,
          timeout: 30000, // 30 seconds for file upload
        }
      );

      return response.data.url;
    } catch (error) {
      console.error('Failed to upload attachment:', error);
      return null;
    }
  }

  /**
   * Validate feedback request before submission
   */
  validateFeedbackRequest(request: FeedbackRequest): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Subject validation
    if (!request.subject || request.subject.trim().length < 5) {
      errors.push('Subject must be at least 5 characters long');
    }
    if (request.subject && request.subject.length > 100) {
      errors.push('Subject must be less than 100 characters');
    }

    // Message validation
    if (!request.message || request.message.trim().length < 10) {
      errors.push('Message must be at least 10 characters long');
    }
    if (request.message && request.message.length > 2000) {
      errors.push('Message must be less than 2000 characters');
    }

    // Email validation (if provided)
    if (request.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(request.email)) {
        errors.push('Please enter a valid email address');
      }
    }

    // Rating validation (if provided)
    if (request.rating !== undefined) {
      if (request.rating < 1 || request.rating > 5 || !Number.isInteger(request.rating)) {
        errors.push('Rating must be an integer between 1 and 5');
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Get device and browser information for feedback context
   */
  getDeviceInfo() {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      language: navigator.language,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Collect error logs from console (if available)
   */
  collectErrorLogs(): string[] {
    // This is a simplified version - in a real app you might want to
    // implement a more sophisticated error logging system
    const logs: string[] = [];
    
    // Check if there are any stored error logs
    const storedLogs = localStorage.getItem('app_error_logs');
    if (storedLogs) {
      try {
        const parsedLogs = JSON.parse(storedLogs);
        logs.push(...parsedLogs);
      } catch (e) {
        console.warn('Failed to parse stored error logs');
      }
    }

    return logs;
  }
}

// Singleton instance
export const feedbackService = new FeedbackService();