import axios from 'axios';
import { FeedbackService } from '../FeedbackService';
import { FeedbackSubmitRequest } from '../../models/Feedback';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('FeedbackService', () => {
  let service: FeedbackService;
  let mockCreate: jest.Mock;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup axios.create mock
    mockCreate = jest.fn().mockReturnValue({
      post: jest.fn(),
      get: jest.fn(),
      interceptors: {
        request: {
          use: jest.fn(),
        },
      },
    });

    mockedAxios.create = mockCreate;

    service = new FeedbackService('https://api.test.com');
  });

  describe('submitFeedback', () => {
    it('should submit feedback successfully', async () => {
      const feedbackRequest: FeedbackSubmitRequest = {
        feedbackType: 'bug',
        title: 'Test Bug',
        message: 'This is a test bug report',
        category: 'general',
        allowContact: false,
      };

      const mockResponse = {
        data: {
          success: true,
          feedbackId: 'feedback-123',
          message: 'Feedback submitted successfully',
        },
      };

      const mockPost = jest.fn().mockResolvedValue(mockResponse);
      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.submitFeedback(feedbackRequest);

      expect(result.success).toBe(true);
      expect(result.feedbackId).toBe('feedback-123');
      expect(mockPost).toHaveBeenCalledWith(
        '/feedback',
        expect.objectContaining({
          feedbackType: 'bug',
          title: 'Test Bug',
          message: 'This is a test bug report',
        })
      );
    });

    it('should handle submission errors', async () => {
      const feedbackRequest: FeedbackSubmitRequest = {
        feedbackType: 'bug',
        title: 'Test Bug',
        message: 'This is a test bug report',
        category: 'general',
        allowContact: false,
      };

      const mockError = {
        response: {
          data: {
            error: 'Validation failed',
          },
        },
      };

      const mockPost = jest.fn().mockRejectedValue(mockError);
      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.submitFeedback(feedbackRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Validation failed');
    });
  });

  describe('getFeedback', () => {
    it('should retrieve feedback successfully', async () => {
      const mockFeedback = [
        {
          id: 'feedback-1',
          userId: 'user-123',
          feedbackType: 'bug',
          title: 'Test Bug',
          message: 'Test message',
          category: 'general',
          createdAt: new Date(),
          status: 'pending',
          allowContact: false,
        },
      ];

      const mockResponse = {
        data: {
          success: true,
          feedback: mockFeedback,
        },
      };

      const mockGet = jest.fn().mockResolvedValue(mockResponse);
      mockCreate.mockReturnValue({
        post: jest.fn(),
        get: mockGet,
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.getFeedback();

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('feedback-1');
      expect(mockGet).toHaveBeenCalledWith('/feedback');
    });

    it('should return empty array on error', async () => {
      const mockGet = jest.fn().mockRejectedValue(new Error('Network error'));
      mockCreate.mockReturnValue({
        post: jest.fn(),
        get: mockGet,
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.getFeedback();

      expect(result).toEqual([]);
    });
  });

  describe('trackEvent', () => {
    it('should track event successfully', async () => {
      const mockResponse = {
        data: {
          success: true,
          metricId: 'metric-123',
          message: 'Metric tracked successfully',
        },
      };

      const mockPost = jest.fn().mockResolvedValue(mockResponse);
      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.trackEvent(
        'action',
        'button_click',
        { buttonId: 'submit' }
      );

      expect(result).toBe(true);
      expect(mockPost).toHaveBeenCalledWith(
        '/metrics/track',
        expect.objectContaining({
          eventType: 'action',
          eventName: 'button_click',
          properties: expect.objectContaining({
            buttonId: 'submit',
          }),
        })
      );
    });

    it('should silently fail on error', async () => {
      const mockPost = jest.fn().mockRejectedValue(new Error('Network error'));
      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const result = await service.trackEvent('action', 'button_click');

      expect(result).toBe(false);
    });
  });

  describe('trackPageView', () => {
    it('should track page view', async () => {
      const mockPost = jest.fn().mockResolvedValue({
        data: { success: true },
      });

      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      await service.trackPageView('/home');

      expect(mockPost).toHaveBeenCalledWith(
        '/metrics/track',
        expect.objectContaining({
          eventType: 'navigation',
          eventName: 'page_view',
          properties: expect.objectContaining({
            page: '/home',
          }),
        })
      );
    });
  });

  describe('trackError', () => {
    it('should track error', async () => {
      const mockPost = jest.fn().mockResolvedValue({
        data: { success: true },
      });

      mockCreate.mockReturnValue({
        post: mockPost,
        get: jest.fn(),
        interceptors: {
          request: {
            use: jest.fn(),
          },
        },
      });

      service = new FeedbackService('https://api.test.com');

      const error = new Error('Test error');
      await service.trackError(error, { context: 'test' });

      expect(mockPost).toHaveBeenCalledWith(
        '/metrics/track',
        expect.objectContaining({
          eventType: 'error',
          eventName: 'Error',
          properties: expect.objectContaining({
            message: 'Test error',
            context: 'test',
          }),
        })
      );
    });
  });
});
