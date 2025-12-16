import axios, { AxiosInstance } from 'axios';
import {
  Feedback,
  FeedbackSubmitRequest,
  FeedbackSubmitResponse,
  MetricTrackRequest,
  MetricTrackResponse,
  UserMetric,
} from '../models/Feedback';

/**
 * Service for handling user feedback and metrics collection
 */
export class FeedbackService {
  private apiClient: AxiosInstance;
  private sessionId: string;

  constructor(baseURL?: string) {
    this.apiClient = axios.create({
      baseURL: baseURL || process.env.REACT_APP_API_BASE_URL || '/api',
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Generate session ID for tracking user session
    this.sessionId = this.generateSessionId();

    // Add interceptor to include auth token
    this.apiClient.interceptors.request.use(
      (config) => {
        const token = this.getAuthToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );
  }

  /**
   * Submit user feedback
   */
  async submitFeedback(
    feedback: FeedbackSubmitRequest
  ): Promise<FeedbackSubmitResponse> {
    try {
      // Add page context and device info
      const enrichedFeedback = {
        ...feedback,
        pageContext: feedback.pageContext || window.location.pathname,
      };

      const response = await this.apiClient.post<FeedbackSubmitResponse>(
        '/feedback',
        enrichedFeedback
      );

      // Track that user submitted feedback
      await this.trackEvent('feedback', 'feedback_submitted', {
        feedbackType: feedback.feedbackType,
        category: feedback.category,
        hasRating: !!feedback.rating,
      });

      return response.data;
    } catch (error: any) {
      console.error('Failed to submit feedback:', error);
      return {
        success: false,
        message: 'Failed to submit feedback',
        error: error.response?.data?.error || error.message,
      };
    }
  }

  /**
   * Get user's feedback history
   */
  async getFeedback(): Promise<Feedback[]> {
    try {
      const response = await this.apiClient.get<{
        success: boolean;
        feedback: Feedback[];
      }>('/feedback');

      return response.data.feedback || [];
    } catch (error) {
      console.error('Failed to get feedback:', error);
      return [];
    }
  }

  /**
   * Track a user event/metric
   */
  async trackEvent(
    eventType: string,
    eventName: string,
    properties?: Record<string, any>,
    duration?: number
  ): Promise<boolean> {
    try {
      const metricRequest: MetricTrackRequest = {
        eventType,
        eventName,
        properties: {
          ...properties,
          ...this.getDeviceInfo(),
        },
        sessionId: this.sessionId,
        page: window.location.pathname,
        duration,
      };

      const response = await this.apiClient.post<MetricTrackResponse>(
        '/metrics/track',
        metricRequest
      );

      return response.data.success;
    } catch (error) {
      // Silently fail metric tracking - don't disrupt user experience
      console.debug('Failed to track metric:', error);
      return false;
    }
  }

  /**
   * Track page view
   */
  async trackPageView(page?: string): Promise<void> {
    await this.trackEvent('navigation', 'page_view', {
      page: page || window.location.pathname,
      referrer: document.referrer,
    });
  }

  /**
   * Track user action
   */
  async trackAction(
    action: string,
    properties?: Record<string, any>
  ): Promise<void> {
    await this.trackEvent('action', action, properties);
  }

  /**
   * Track timing/performance metric
   */
  async trackTiming(
    category: string,
    name: string,
    duration: number,
    properties?: Record<string, any>
  ): Promise<void> {
    await this.trackEvent('timing', `${category}_${name}`, properties, duration);
  }

  /**
   * Track error
   */
  async trackError(
    error: Error,
    context?: Record<string, any>
  ): Promise<void> {
    await this.trackEvent('error', error.name, {
      message: error.message,
      stack: error.stack,
      ...context,
    });
  }

  /**
   * Helper methods
   */

  private generateSessionId(): string {
    // Check if session ID exists in sessionStorage
    const existingSessionId = sessionStorage.getItem('sessionId');
    if (existingSessionId) {
      return existingSessionId;
    }

    // Generate new session ID
    const sessionId = `session_${Date.now()}_${Math.random()
      .toString(36)
      .substr(2, 9)}`;
    sessionStorage.setItem('sessionId', sessionId);
    return sessionId;
  }

  private getAuthToken(): string | null {
    // Get token from localStorage or sessionStorage
    return (
      localStorage.getItem('authToken') ||
      sessionStorage.getItem('authToken')
    );
  }

  private getDeviceInfo(): Record<string, any> {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      screenResolution: `${window.screen.width}x${window.screen.height}`,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      isMobile: this.isMobileDevice(),
      isTablet: this.isTabletDevice(),
      browser: this.getBrowserInfo(),
    };
  }

  private isMobileDevice(): boolean {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
      navigator.userAgent
    );
  }

  private isTabletDevice(): boolean {
    return /iPad|Android/i.test(navigator.userAgent) && !this.isMobileDevice();
  }

  private getBrowserInfo(): string {
    const ua = navigator.userAgent;
    let browser = 'Unknown';

    if (ua.indexOf('Chrome') > -1) {
      browser = 'Chrome';
    } else if (ua.indexOf('Safari') > -1) {
      browser = 'Safari';
    } else if (ua.indexOf('Firefox') > -1) {
      browser = 'Firefox';
    } else if (ua.indexOf('MSIE') > -1 || ua.indexOf('Trident/') > -1) {
      browser = 'Internet Explorer';
    } else if (ua.indexOf('Edge') > -1) {
      browser = 'Edge';
    }

    return browser;
  }
}

// Export singleton instance
export const feedbackService = new FeedbackService();
