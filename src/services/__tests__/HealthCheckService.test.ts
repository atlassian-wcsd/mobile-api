import { HealthCheckService } from '../HealthCheckService';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('HealthCheckService', () => {
  let service: HealthCheckService;

  beforeEach(() => {
    service = new HealthCheckService('https://test-api.example.com');
    jest.clearAllMocks();
  });

  describe('getHealthStatus', () => {
    it('should return health status on successful request', async () => {
      const mockResponse = {
        status: 'healthy' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'healthy' as const, responseTimeMs: 50 },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 40,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockResolvedValue({ data: mockResponse });

      const result = await service.getHealthStatus();

      expect(result).toEqual(mockResponse);
      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://test-api.example.com/health',
        expect.objectContaining({
          timeout: 10000,
        })
      );
    });

    it('should return degraded status on 503 response', async () => {
      const mockResponse = {
        status: 'degraded' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'unhealthy' as const, responseTimeMs: 100, message: 'Connection failed' },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 65,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockRejectedValue({
        isAxiosError: true,
        response: { status: 503, data: mockResponse },
        message: 'Request failed with status code 503',
      });

      mockedAxios.isAxiosError.mockReturnValue(true);

      const result = await service.getHealthStatus();

      expect(result).toEqual(mockResponse);
    });

    it('should throw error on network failure', async () => {
      mockedAxios.get.mockRejectedValue({
        isAxiosError: true,
        message: 'Network Error',
      });

      mockedAxios.isAxiosError.mockReturnValue(true);

      await expect(service.getHealthStatus()).rejects.toThrow('Health check failed');
    });
  });

  describe('isHealthy', () => {
    it('should return true when status is healthy', async () => {
      const mockResponse = {
        status: 'healthy' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'healthy' as const, responseTimeMs: 50 },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 40,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockResolvedValue({ data: mockResponse });

      const result = await service.isHealthy();

      expect(result).toBe(true);
    });

    it('should return false when status is degraded', async () => {
      const mockResponse = {
        status: 'degraded' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'unhealthy' as const, responseTimeMs: 100 },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 65,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockResolvedValue({ data: mockResponse });

      const result = await service.isHealthy();

      expect(result).toBe(false);
    });

    it('should return false on error', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));
      mockedAxios.isAxiosError.mockReturnValue(false);

      const result = await service.isHealthy();

      expect(result).toBe(false);
    });
  });

  describe('getAverageResponseTime', () => {
    it('should return average response time on success', async () => {
      const mockResponse = {
        status: 'healthy' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'healthy' as const, responseTimeMs: 50 },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 42.5,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockResolvedValue({ data: mockResponse });

      const result = await service.getAverageResponseTime();

      expect(result).toBe(42.5);
    });

    it('should return -1 on error', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));
      mockedAxios.isAxiosError.mockReturnValue(false);

      const result = await service.getAverageResponseTime();

      expect(result).toBe(-1);
    });
  });

  describe('setBaseUrl', () => {
    it('should update the base URL', async () => {
      service.setBaseUrl('https://new-api.example.com');

      const mockResponse = {
        status: 'healthy' as const,
        timestamp: '2023-01-01T00:00:00Z',
        version: '1.0.0',
        services: {
          s3: { status: 'healthy' as const, responseTimeMs: 50 },
          dynamodb: { status: 'healthy' as const, responseTimeMs: 30 },
        },
        performance: {
          averageResponseTimeMs: 40,
          uptime: 'operational',
        },
      };

      mockedAxios.get.mockResolvedValue({ data: mockResponse });

      await service.getHealthStatus();

      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://new-api.example.com/health',
        expect.any(Object)
      );
    });
  });
});
