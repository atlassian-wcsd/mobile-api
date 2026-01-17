import axios, { AxiosError } from 'axios';
import { HealthCheckResponse } from '../models/HealthCheck';

/**
 * Service class for managing health check operations
 */
export class HealthCheckService {
  private baseUrl: string;

  constructor(baseUrl?: string) {
    // Default to API Gateway endpoint or allow override
    this.baseUrl = baseUrl || process.env.REACT_APP_API_URL || 'https://api.yourapp.com/v1';
  }

  /**
   * Fetch the current health status of the API
   * @returns Promise with health check response
   * @throws Error if the health check fails
   */
  public async getHealthStatus(): Promise<HealthCheckResponse> {
    try {
      const response = await axios.get<HealthCheckResponse>(`${this.baseUrl}/health`, {
        timeout: 10000, // 10 second timeout
        headers: {
          'Content-Type': 'application/json',
        },
      });

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError<HealthCheckResponse>;
        
        // If we get a 503, the API is responding but degraded
        if (axiosError.response?.status === 503 && axiosError.response?.data) {
          return axiosError.response.data;
        }

        throw new Error(
          `Health check failed: ${axiosError.message}${
            axiosError.response?.data ? ` - ${JSON.stringify(axiosError.response.data)}` : ''
          }`
        );
      }
      
      throw new Error(`Unexpected error during health check: ${error}`);
    }
  }

  /**
   * Perform a periodic health check
   * @param intervalMs Interval in milliseconds for periodic checks
   * @param callback Callback function to handle health check results
   * @returns Function to stop the periodic checks
   */
  public startPeriodicHealthCheck(
    intervalMs: number,
    callback: (health: HealthCheckResponse | null, error: Error | null) => void
  ): () => void {
    const intervalId = setInterval(async () => {
      try {
        const health = await this.getHealthStatus();
        callback(health, null);
      } catch (error) {
        callback(null, error as Error);
      }
    }, intervalMs);

    // Return a function to stop the periodic checks
    return () => clearInterval(intervalId);
  }

  /**
   * Check if the API is healthy
   * @returns Promise<boolean> indicating if API is healthy
   */
  public async isHealthy(): Promise<boolean> {
    try {
      const health = await this.getHealthStatus();
      return health.status === 'healthy';
    } catch {
      return false;
    }
  }

  /**
   * Get the average response time from the health check
   * @returns Promise<number> average response time in milliseconds, or -1 if unavailable
   */
  public async getAverageResponseTime(): Promise<number> {
    try {
      const health = await this.getHealthStatus();
      return health.performance.averageResponseTimeMs;
    } catch {
      return -1;
    }
  }

  /**
   * Set the base URL for the health check service
   * @param baseUrl New base URL
   */
  public setBaseUrl(baseUrl: string): void {
    this.baseUrl = baseUrl;
  }
}
