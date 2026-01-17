/**
 * Health check response model
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'degraded';
  timestamp: string;
  version: string;
  services: ServiceHealthStatus;
  performance: PerformanceMetrics;
}

/**
 * Service health status container
 */
export interface ServiceHealthStatus {
  s3: ServiceStatus;
  dynamodb: ServiceStatus;
}

/**
 * Individual service status
 */
export interface ServiceStatus {
  status: 'healthy' | 'unhealthy';
  responseTimeMs: number;
  message?: string;
}

/**
 * Performance metrics
 */
export interface PerformanceMetrics {
  averageResponseTimeMs: number;
  uptime: string;
}
