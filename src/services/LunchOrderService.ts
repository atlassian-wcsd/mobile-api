import axios, { AxiosInstance } from 'axios';
import {
  LunchOrder,
  LunchOrderSubmitRequest,
  LunchOrderSubmitResponse,
  ValidationError,
  ValidationResult,
} from '../models/LunchOrder';
import { feedbackService } from './FeedbackService';

/**
 * Service for handling lunch order submissions and validation
 */
export class LunchOrderService {
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
   * Validate lunch order input
   */
  validateLunchOrder(
    orderData: Partial<LunchOrderSubmitRequest>
  ): ValidationResult {
    const errors: ValidationError[] = [];

    // Validate name (required)
    if (!orderData.name || orderData.name.trim().length === 0) {
      errors.push({
        field: 'name',
        message: 'Name is required',
        value: orderData.name,
      });
    } else if (orderData.name.trim().length < 2) {
      errors.push({
        field: 'name',
        message: 'Name must be at least 2 characters',
        value: orderData.name,
      });
    } else if (orderData.name.length > 100) {
      errors.push({
        field: 'name',
        message: 'Name must not exceed 100 characters',
        value: orderData.name,
      });
    }

    // Validate email (optional but validated if provided)
    if (orderData.email && orderData.email.trim().length > 0) {
      if (!this.isValidEmail(orderData.email)) {
        errors.push({
          field: 'email',
          message: 'Please enter a valid email address',
          value: orderData.email,
        });
      } else if (orderData.email.length > 254) {
        errors.push({
          field: 'email',
          message: 'Email must not exceed 254 characters',
          value: orderData.email,
        });
      }
    }

    // Validate menu selection (required)
    if (!orderData.menuSelection || orderData.menuSelection.trim().length === 0) {
      errors.push({
        field: 'menuSelection',
        message: 'Menu selection is required',
        value: orderData.menuSelection,
      });
    } else if (orderData.menuSelection.length > 200) {
      errors.push({
        field: 'menuSelection',
        message: 'Menu selection must not exceed 200 characters',
        value: orderData.menuSelection,
      });
    }

    // Validate quantity (required, minimum 1)
    if (orderData.quantity === undefined || orderData.quantity === null) {
      errors.push({
        field: 'quantity',
        message: 'Quantity is required',
        value: orderData.quantity,
      });
    } else if (!Number.isInteger(orderData.quantity) || orderData.quantity < 1) {
      errors.push({
        field: 'quantity',
        message: 'Quantity must be a positive integer',
        value: orderData.quantity,
      });
    } else if (orderData.quantity > 1000) {
      errors.push({
        field: 'quantity',
        message: 'Quantity must not exceed 1000',
        value: orderData.quantity,
      });
    }

    // Validate special instructions (optional but with length limit)
    if (
      orderData.specialInstructions &&
      orderData.specialInstructions.length > 1000
    ) {
      errors.push({
        field: 'specialInstructions',
        message: 'Special instructions must not exceed 1000 characters',
        value: orderData.specialInstructions,
      });
    }

    // Validate delivery location (optional but with length limit)
    if (
      orderData.deliveryLocation &&
      orderData.deliveryLocation.length > 500
    ) {
      errors.push({
        field: 'deliveryLocation',
        message: 'Delivery location must not exceed 500 characters',
        value: orderData.deliveryLocation,
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Submit a lunch order
   */
  async submitLunchOrder(
    orderData: LunchOrderSubmitRequest
  ): Promise<LunchOrderSubmitResponse> {
    try {
      // Validate order data
      const validationResult = this.validateLunchOrder(orderData);

      if (!validationResult.isValid) {
        // Track validation error
        await feedbackService.trackEvent('lunch_order', 'order_validation_failed', {
          fieldErrors: validationResult.errors.map((e) => e.field),
          errorCount: validationResult.errors.length,
        });

        return {
          success: false,
          message: 'Order validation failed',
          error: 'Please correct the highlighted fields',
          validationErrors: this.mapValidationErrors(validationResult.errors),
        };
      }

      // Add page context
      const enrichedOrder = {
        ...orderData,
        pageContext: window.location.pathname,
      };

      const response = await this.apiClient.post<LunchOrderSubmitResponse>(
        '/lunch-orders',
        enrichedOrder
      );

      // Track successful submission
      await feedbackService.trackEvent('lunch_order', 'order_submitted', {
        menuSelection: orderData.menuSelection,
        quantity: orderData.quantity,
        hasEmail: !!orderData.email,
        hasSpecialInstructions: !!orderData.specialInstructions,
      });

      return response.data;
    } catch (error: any) {
      console.error('Failed to submit lunch order:', error);

      // Track error
      await feedbackService.trackError(
        new Error('Failed to submit lunch order'),
        {
          errorDetails: error.response?.data?.error || error.message,
          status: error.response?.status,
        }
      );

      return {
        success: false,
        message: 'Failed to submit order',
        error: error.response?.data?.error || error.message,
      };
    }
  }

  /**
   * Get user's lunch orders
   */
  async getLunchOrders(): Promise<LunchOrder[]> {
    try {
      const response = await this.apiClient.get<{
        success: boolean;
        orders: LunchOrder[];
      }>('/lunch-orders');

      return response.data.orders || [];
    } catch (error) {
      console.error('Failed to get lunch orders:', error);
      return [];
    }
  }

  /**
   * Get a specific lunch order by ID
   */
  async getLunchOrderById(orderId: string): Promise<LunchOrder | null> {
    try {
      const response = await this.apiClient.get<{
        success: boolean;
        order: LunchOrder;
      }>(`/lunch-orders/${orderId}`);

      return response.data.order || null;
    } catch (error) {
      console.error('Failed to get lunch order:', error);
      return null;
    }
  }

  /**
   * Cancel a lunch order
   */
  async cancelLunchOrder(orderId: string): Promise<boolean> {
    try {
      await this.apiClient.post(`/lunch-orders/${orderId}/cancel`, {});

      // Track cancellation
      await feedbackService.trackEvent('lunch_order', 'order_cancelled', {
        orderId,
      });

      return true;
    } catch (error) {
      console.error('Failed to cancel lunch order:', error);
      return false;
    }
  }

  /**
   * Helper methods
   */

  private isValidEmail(email: string): boolean {
    // RFC 5322 simplified email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private generateSessionId(): string {
    const existingSessionId = sessionStorage.getItem('sessionId');
    if (existingSessionId) {
      return existingSessionId;
    }

    const sessionId = `session_${Date.now()}_${Math.random()
      .toString(36)
      .substr(2, 9)}`;
    sessionStorage.setItem('sessionId', sessionId);
    return sessionId;
  }

  private getAuthToken(): string | null {
    return (
      localStorage.getItem('authToken') ||
      sessionStorage.getItem('authToken')
    );
  }

  private mapValidationErrors(
    errors: ValidationError[]
  ): Record<string, string> {
    return errors.reduce(
      (acc, error) => {
        acc[error.field] = error.message;
        return acc;
      },
      {} as Record<string, string>
    );
  }
}

// Export singleton instance
export const lunchOrderService = new LunchOrderService();
