import {
  InfrastructureMetrics,
  InfrastructureMetricsResponse,
  MetricsHistoryPoint,
  MetricsAlert,
  MetricsFeedback,
  MetricsConfiguration
} from '../types/InfrastructureMetrics';

export class InfrastructureMetricsService {
  private baseUrl: string;
  private refreshInterval: number;
  private intervalId: number | null = null;

  constructor() {
    this.baseUrl = process.env.REACT_APP_METRICS_API_URL || '/api/metrics';
    this.refreshInterval = 30000; // Default 30 seconds
  }

  /**
   * Fetch current infrastructure metrics
   */
  async getCurrentMetrics(): Promise<InfrastructureMetrics> {
    try {
      const response = await this.makeRequest(`${this.baseUrl}/current`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch metrics: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return this.transformMetricsData(data);
    } catch (error) {
      console.error('Error fetching current metrics:', error);
      throw new Error('Unable to fetch current infrastructure metrics');
    }
  }

  /**
   * Fetch comprehensive metrics including history and alerts
   */
  async getMetricsOverview(): Promise<InfrastructureMetricsResponse> {
    try {
      const response = await this.makeRequest(`${this.baseUrl}/overview`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch metrics overview: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return {
        current: this.transformMetricsData(data.current),
        history: data.history.map((point: any) => ({
          ...point,
          timestamp: new Date(point.timestamp)
        })),
        alerts: data.alerts.map((alert: any) => ({
          ...alert,
          timestamp: new Date(alert.timestamp)
        }))
      };
    } catch (error) {
      console.error('Error fetching metrics overview:', error);
      throw new Error('Unable to fetch infrastructure metrics overview');
    }
  }

  /**
   * Fetch historical metrics for a specific time range
   */
  async getHistoricalMetrics(
    startTime: Date,
    endTime: Date,
    interval: '1m' | '5m' | '15m' | '1h' = '5m'
  ): Promise<MetricsHistoryPoint[]> {
    try {
      const params = new URLSearchParams({
        start: startTime.toISOString(),
        end: endTime.toISOString(),
        interval
      });

      const response = await this.makeRequest(`${this.baseUrl}/history?${params}`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch historical metrics: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.map((point: any) => ({
        ...point,
        timestamp: new Date(point.timestamp)
      }));
    } catch (error) {
      console.error('Error fetching historical metrics:', error);
      throw new Error('Unable to fetch historical metrics');
    }
  }

  /**
   * Get active alerts
   */
  async getActiveAlerts(): Promise<MetricsAlert[]> {
    try {
      const response = await this.makeRequest(`${this.baseUrl}/alerts`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch alerts: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.map((alert: any) => ({
        ...alert,
        timestamp: new Date(alert.timestamp)
      }));
    } catch (error) {
      console.error('Error fetching alerts:', error);
      return []; // Return empty array on error to not break the UI
    }
  }

  /**
   * Submit user feedback about the metrics display
   */
  async submitFeedback(feedback: Omit<MetricsFeedback, 'timestamp'>): Promise<void> {
    try {
      const feedbackData = {
        ...feedback,
        timestamp: new Date().toISOString()
      };

      const response = await this.makeRequest(`${this.baseUrl}/feedback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(feedbackData)
      });

      if (!response.ok) {
        throw new Error(`Failed to submit feedback: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error submitting feedback:', error);
      throw new Error('Unable to submit feedback');
    }
  }

  /**
   * Get metrics configuration
   */
  async getConfiguration(): Promise<MetricsConfiguration> {
    try {
      const response = await this.makeRequest(`${this.baseUrl}/config`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch configuration: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error fetching configuration:', error);
      // Return default configuration on error
      return {
        refreshInterval: 30000,
        historyDuration: 60,
        alertThresholds: {
          cpu: 80,
          memory: 85,
          io: 90,
          network: 95
        }
      };
    }
  }

  /**
   * Start automatic metrics refresh
   */
  startAutoRefresh(callback: (metrics: InfrastructureMetrics) => void, interval?: number): void {
    if (this.intervalId) {
      this.stopAutoRefresh();
    }

    this.refreshInterval = interval || this.refreshInterval;
    
    // Initial fetch
    this.getCurrentMetrics()
      .then(callback)
      .catch(error => console.error('Error in initial metrics fetch:', error));

    // Set up interval
    this.intervalId = window.setInterval(async () => {
      try {
        const metrics = await this.getCurrentMetrics();
        callback(metrics);
      } catch (error) {
        console.error('Error in auto-refresh:', error);
      }
    }, this.refreshInterval);
  }

  /**
   * Stop automatic metrics refresh
   */
  stopAutoRefresh(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /**
   * Check if service is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.makeRequest(`${this.baseUrl}/health`);
      return response.ok;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }

  /**
   * Transform raw metrics data from API
   */
  private transformMetricsData(data: any): InfrastructureMetrics {
    return {
      ...data,
      timestamp: new Date(data.timestamp)
    };
  }

  /**
   * Make HTTP request with error handling
   */
  private async makeRequest(url: string, options: RequestInit = {}): Promise<Response> {
    const defaultOptions: RequestInit = {
      headers: {
        'Accept': 'application/json',
        ...options.headers
      },
      ...options
    };

    try {
      const response = await fetch(url, defaultOptions);
      return response;
    } catch (error) {
      console.error('Network request failed:', error);
      throw new Error('Network request failed');
    }
  }
}

/**
 * Utility functions for metrics processing
 */
export class MetricsUtils {
  /**
   * Format bytes to human readable format
   */
  static formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Format percentage with appropriate precision
   */
  static formatPercentage(value: number): string {
    return `${value.toFixed(1)}%`;
  }

  /**
   * Format uptime to human readable format
   */
  static formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  }

  /**
   * Get status color based on metric value and threshold
   */
  static getStatusColor(value: number, threshold: number): string {
    if (value >= threshold) return '#ff4757'; // Critical - red
    if (value >= threshold * 0.8) return '#ffa502'; // Warning - orange
    return '#2ed573'; // Healthy - green
  }

  /**
   * Determine overall service status based on metrics
   */
  static determineServiceStatus(metrics: InfrastructureMetrics): 'healthy' | 'warning' | 'critical' | 'unknown' {
    const { cpu, memory, io } = metrics;
    
    // Critical thresholds
    if (cpu.usage >= 95 || memory.usage >= 95 || io.diskUsage >= 95) {
      return 'critical';
    }
    
    // Warning thresholds
    if (cpu.usage >= 80 || memory.usage >= 85 || io.diskUsage >= 90) {
      return 'warning';
    }
    
    return 'healthy';
  }
}