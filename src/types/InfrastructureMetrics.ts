export interface CPUMetrics {
  usage: number; // Percentage (0-100)
  cores: number;
  loadAverage: {
    oneMinute: number;
    fiveMinutes: number;
    fifteenMinutes: number;
  };
}

export interface MemoryMetrics {
  usage: number; // Percentage (0-100)
  total: number; // Total memory in MB
  used: number; // Used memory in MB
  available: number; // Available memory in MB
  cached: number; // Cached memory in MB
}

export interface IOMetrics {
  readThroughput: number; // MB/s
  writeThroughput: number; // MB/s
  readIOPS: number; // Operations per second
  writeIOPS: number; // Operations per second
  diskUsage: number; // Percentage (0-100)
}

export interface NetworkMetrics {
  inboundThroughput: number; // MB/s
  outboundThroughput: number; // MB/s
  packetsPerSecond: number;
  connectionsActive: number;
  connectionsTotal: number;
}

export interface InfrastructureMetrics {
  timestamp: Date;
  cpu: CPUMetrics;
  memory: MemoryMetrics;
  io: IOMetrics;
  network: NetworkMetrics;
  serviceStatus: 'healthy' | 'warning' | 'critical' | 'unknown';
  uptime: number; // Uptime in seconds
}

export interface MetricsHistoryPoint {
  timestamp: Date;
  cpu: number;
  memory: number;
  io: number;
  network: number;
}

export interface InfrastructureMetricsResponse {
  current: InfrastructureMetrics;
  history: MetricsHistoryPoint[];
  alerts: MetricsAlert[];
}

export interface MetricsAlert {
  id: string;
  type: 'cpu' | 'memory' | 'io' | 'network' | 'general';
  severity: 'warning' | 'critical';
  message: string;
  timestamp: Date;
  resolved: boolean;
}

export interface MetricsFeedback {
  userId?: string;
  rating: 1 | 2 | 3 | 4 | 5;
  comment: string;
  category: 'display' | 'accuracy' | 'performance' | 'feature_request' | 'other';
  timestamp: Date;
}

export interface MetricsConfiguration {
  refreshInterval: number; // Refresh interval in milliseconds
  historyDuration: number; // History duration in minutes
  alertThresholds: {
    cpu: number;
    memory: number;
    io: number;
    network: number;
  };
}