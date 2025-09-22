import axios, { AxiosResponse } from 'axios';
import { 
  InfrastructureMetrics, 
  InfrastructureMetricsResponse, 
  MetricsHistoryRequest, 
  MetricsHistoryResponse,
  InfrastructureMetricsBuilder 
} from '../models/InfrastructureMetrics';

export class InfrastructureMetricsService {
  private readonly baseURL: string;
  private readonly timeout: number;

  constructor() {
    this.baseURL = process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com/v1';
    this.timeout = 10000; // 10 seconds
  }

  /**
   * Fetches current infrastructure metrics
   */
  async getCurrentMetrics(): Promise<InfrastructureMetrics> {
    try {
      const response: AxiosResponse<InfrastructureMetricsResponse> = await this.makeRequest(
        '/infrastructure/metrics/current',
        {
          method: 'GET'
        }
      );

      if (!response.data.success || !response.data.data) {
        throw new Error(response.data.error || 'Failed to fetch current metrics');
      }

      return this.parseMetricsResponse(response.data.data);
    } catch (error) {
      console.error('Error fetching current infrastructure metrics:', error);
      throw new Error(
        error instanceof Error ? error.message : 'Failed to fetch infrastructure metrics'
      );
    }
  }

  /**
   * Fetches historical infrastructure metrics
   */
  async getMetricsHistory(request: MetricsHistoryRequest): Promise<InfrastructureMetrics[]> {
    try {
      const response: AxiosResponse<MetricsHistoryResponse> = await this.makeRequest(
        '/infrastructure/metrics/history',
        {
          method: 'POST',
          data: request
        }
      );

      if (!response.data.success || !response.data.data) {
        throw new Error(response.data.error || 'Failed to fetch metrics history');
      }

      return response.data.data.map(metrics => this.parseMetricsResponse(metrics));
    } catch (error) {
      console.error('Error fetching infrastructure metrics history:', error);
      throw new Error(
        error instanceof Error ? error.message : 'Failed to fetch metrics history'
      );
    }
  }

  /**
   * Fetches metrics for a specific time range with real-time updates
   */
  async getMetricsStream(
    timeRange: string = '1h',
    onUpdate: (metrics: InfrastructureMetrics) => void,
    onError: (error: string) => void
  ): Promise<() => void> {
    let intervalId: NodeJS.Timeout;
    let isActive = true;

    const fetchMetrics = async () => {
      if (!isActive) return;

      try {
        const metrics = await this.getCurrentMetrics();
        onUpdate(metrics);
      } catch (error) {
        onError(error instanceof Error ? error.message : 'Failed to fetch metrics');
      }
    };

    // Initial fetch
    await fetchMetrics();

    // Set up polling for real-time updates (every 30 seconds)
    intervalId = setInterval(fetchMetrics, 30000);

    // Return cleanup function
    return () => {
      isActive = false;
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }

  /**
   * Validates if the metrics service is available
   */
  async validateService(): Promise<boolean> {
    try {
      const response: AxiosResponse = await this.makeRequest('/infrastructure/health', {
        method: 'GET'
      });
      return response.status === 200;
    } catch (error) {
      console.warn('Infrastructure metrics service is not available:', error);
      return false;
    }
  }

  /**
   * Gets aggregated metrics summary
   */
  async getMetricsSummary(timeRange: string = '24h'): Promise<{
    averageCpuUsage: number;
    averageMemoryUsage: number;
    averageResponseTime: number;
    totalRequests: number;
    errorRate: number;
  }> {
    try {
      const response: AxiosResponse = await this.makeRequest(
        `/infrastructure/metrics/summary?timeRange=${timeRange}`,
        {
          method: 'GET'
        }
      );

      if (!response.data.success) {
        throw new Error(response.data.error || 'Failed to fetch metrics summary');
      }

      return response.data.data;
    } catch (error) {
      console.error('Error fetching metrics summary:', error);
      throw new Error(
        error instanceof Error ? error.message : 'Failed to fetch metrics summary'
      );
    }
  }

  /**
   * Parses and validates metrics response
   */
  private parseMetricsResponse(data: any): InfrastructureMetrics {
    try {
      return new InfrastructureMetricsBuilder()
        .setTimestamp(new Date(data.timestamp))
        .setProcessorUsage(data.processorUsage)
        .setRamUsage(data.ramUsage)
        .setIOPerformance(data.ioPerformance)
        .setThroughput(data.throughput)
        .setContainerInfo(data.containerInfo)
        .build();
    } catch (error) {
      throw new Error(`Invalid metrics data format: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Makes HTTP request with proper error handling
   */
  private async makeRequest(endpoint: string, options: any = {}): Promise<AxiosResponse> {
    const config = {
      url: `${this.baseURL}${endpoint}`,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    try {
      return await axios(config);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response) {
          // Server responded with error status
          throw new Error(
            error.response.data?.error || 
            error.response.data?.message || 
            `HTTP ${error.response.status}: ${error.response.statusText}`
          );
        } else if (error.request) {
          // Request was made but no response received
          throw new Error('Network error: Unable to reach the metrics service');
        }
      }
      throw error;
    }
  }
}

export class InfrastructureMetricsUtils {
  /**
   * Generates mock metrics for development/testing
   */
  static generateMockMetrics(): InfrastructureMetrics {
    const now = new Date();
    
    return new InfrastructureMetricsBuilder()
      .setTimestamp(now)
      .setProcessorUsage({
        cpuUsagePercent: Math.random() * 100,
        loadAverage: {
          oneMinute: Math.random() * 4,
          fiveMinutes: Math.random() * 4,
          fifteenMinutes: Math.random() * 4
        },
        coreCount: 4,
        frequency: 2400
      })
      .setRamUsage({
        totalMemoryMB: 8192,
        usedMemoryMB: Math.random() * 6144 + 1024,
        freeMemoryMB: 0,
        usagePercent: 0,
        buffersCacheMB: Math.random() * 512,
        swapUsedMB: Math.random() * 1024,
        swapTotalMB: 2048
      })
      .setIOPerformance({
        diskUsage: {
          totalSpaceGB: 100,
          usedSpaceGB: Math.random() * 80 + 10,
          freeSpaceGB: 0,
          usagePercent: 0
        },
        diskIO: {
          readBytesPerSecond: Math.random() * 1000000,
          writeBytesPerSecond: Math.random() * 500000,
          readOperationsPerSecond: Math.random() * 100,
          writeOperationsPerSecond: Math.random() * 50
        },
        networkIO: {
          inboundBytesPerSecond: Math.random() * 10000000,
          outboundBytesPerSecond: Math.random() * 5000000,
          inboundPacketsPerSecond: Math.random() * 1000,
          outboundPacketsPerSecond: Math.random() * 800
        }
      })
      .setThroughput({
        requestsPerSecond: Math.random() * 1000,
        responseTimeMs: {
          average: Math.random() * 200 + 50,
          p50: Math.random() * 150 + 30,
          p95: Math.random() * 500 + 100,
          p99: Math.random() * 1000 + 200
        },
        errorRate: Math.random() * 5,
        activeConnections: Math.floor(Math.random() * 500)
      })
      .setContainerInfo({
        containerId: 'container-' + Math.random().toString(36).substring(7),
        containerName: 'signature-app-container',
        imageName: 'signature-app',
        imageTag: 'v1.0.0',
        hostName: 'app-server-01',
        platform: 'linux/amd64',
        uptime: Math.floor(Math.random() * 86400 * 7) // Up to 7 days
      })
      .build();
  }

  /**
   * Calculates derived metrics
   */
  static calculateDerivedMetrics(metrics: InfrastructureMetrics): InfrastructureMetrics {
    // Calculate free memory
    metrics.ramUsage.freeMemoryMB = metrics.ramUsage.totalMemoryMB - metrics.ramUsage.usedMemoryMB;
    
    // Calculate memory usage percentage
    metrics.ramUsage.usagePercent = (metrics.ramUsage.usedMemoryMB / metrics.ramUsage.totalMemoryMB) * 100;
    
    // Calculate disk free space and usage percentage
    metrics.ioPerformance.diskUsage.freeSpaceGB = 
      metrics.ioPerformance.diskUsage.totalSpaceGB - metrics.ioPerformance.diskUsage.usedSpaceGB;
    metrics.ioPerformance.diskUsage.usagePercent = 
      (metrics.ioPerformance.diskUsage.usedSpaceGB / metrics.ioPerformance.diskUsage.totalSpaceGB) * 100;
    
    return metrics;
  }
}