import { 
  Feedback, 
  FeedbackSubmissionRequest, 
  FeedbackSubmissionResponse,
  FeedbackBuilder,
  FeedbackUtils
} from '../models/Feedback';

export class FeedbackService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com/v1';
  }

  /**
   * Submit user feedback to the backend
   */
  async submitFeedback(request: FeedbackSubmissionRequest): Promise<FeedbackSubmissionResponse> {
    try {
      // Validate the request
      this.validateSubmissionRequest(request);

      // Add device info and metadata if not provided
      const enrichedRequest = {
        ...request,
        deviceInfo: request.deviceInfo || FeedbackUtils.getDeviceInfo(),
        metadata: request.metadata || FeedbackUtils.getMetadata()
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
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const result: FeedbackSubmissionResponse = await response.json();
      return result;
    } catch (error) {
      console.error('Failed to submit feedback:', error);
      return {
        success: false,
        message: 'Failed to submit feedback',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Get feedback history for the current user (if authenticated)
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

      const result = await response.json();
      return result.feedback || [];
    } catch (error) {
      console.error('Failed to get feedback history:', error);
      return [];
    }
  }

  /**
   * Get feedback statistics (for admin/analytics purposes)
   */
  async getFeedbackStats(authToken: string): Promise<any> {
    try {
      const response = await this.makeRequest('/feedback/stats', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to get feedback stats:', error);
      throw error;
    }
  }

  /**
   * Validate feedback submission request
   */
  private validateSubmissionRequest(request: FeedbackSubmissionRequest): void {
    const ratingError = FeedbackUtils.validateRating(request.rating);
    if (ratingError) {
      throw new Error(ratingError);
    }

    const textError = FeedbackUtils.validateFeedbackText(request.feedbackText);
    if (textError) {
      throw new Error(textError);
    }

    if (request.contactEmail) {
      const emailError = FeedbackUtils.validateEmail(request.contactEmail);
      if (emailError) {
        throw new Error(emailError);
      }
    }

    if (!request.category) {
      throw new Error('Feedback category is required');
    }
  }

  /**
   * Make HTTP request with proper error handling and CORS support
   */
  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultOptions: RequestInit = {
      mode: 'cors',
      credentials: 'omit',
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const mergedOptions = {
      ...defaultOptions,
      ...options,
      headers: {
        ...defaultOptions.headers,
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, mergedOptions);
      return response;
    } catch (error) {
      console.error(`Request failed for ${url}:`, error);
      throw new Error(`Network error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export class FeedbackServiceUtils {
  /**
   * Create a feedback object from form data
   */
  static createFeedbackFromForm(formData: {
    rating: number;
    feedbackText: string;
    category: string;
    contactEmail?: string;
    userId?: string;
  }): Feedback {
    const builder = new FeedbackBuilder()
      .setRating(formData.rating)
      .setFeedbackText(formData.feedbackText)
      .setCategory(formData.category as any)
      .setDeviceInfo(FeedbackUtils.getDeviceInfo())
      .setMetadata(FeedbackUtils.getMetadata());

    if (formData.contactEmail) {
      builder.setContactEmail(formData.contactEmail);
    }

    if (formData.userId) {
      builder.setUserId(formData.userId);
    }

    return builder.build();
  }

  /**
   * Format feedback for display
   */
  static formatFeedbackForDisplay(feedback: Feedback): string {
    const date = new Date(feedback.createdAt).toLocaleDateString();
    const category = FeedbackUtils.getCategoryDisplayName(feedback.category);
    const rating = '★'.repeat(feedback.rating) + '☆'.repeat(5 - feedback.rating);
    
    return `${date} - ${category} (${rating}): ${feedback.feedbackText.substring(0, 100)}${feedback.feedbackText.length > 100 ? '...' : ''}`;
  }

  /**
   * Check if feedback service is available
   */
  static async checkServiceHealth(): Promise<boolean> {
    try {
      const service = new FeedbackService();
      const response = await service['makeRequest']('/health', { method: 'GET' });
      return response.ok;
    } catch (error) {
      console.warn('Feedback service health check failed:', error);
      return false;
    }
  }
}