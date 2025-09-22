export interface InfrastructureMetrics {
  timestamp: Date;
  processorUsage: ProcessorMetrics;
  ramUsage: MemoryMetrics;
  ioPerformance: IOMetrics;
  throughput: ThroughputMetrics;
  containerInfo: ContainerInfo;
}

export interface ProcessorMetrics {
  cpuUsagePercent: number;
  loadAverage: {
    oneMinute: number;
    fiveMinutes: number;
    fifteenMinutes: number;
  };
  coreCount: number;
  frequency?: number; // MHz
}

export interface MemoryMetrics {
  totalMemoryMB: number;
  usedMemoryMB: number;
  freeMemoryMB: number;
  usagePercent: number;
  buffersCacheMB?: number;
  swapUsedMB?: number;
  swapTotalMB?: number;
}

export interface IOMetrics {
  diskUsage: {
    totalSpaceGB: number;
    usedSpaceGB: number;
    freeSpaceGB: number;
    usagePercent: number;
  };
  diskIO: {
    readBytesPerSecond: number;
    writeBytesPerSecond: number;
    readOperationsPerSecond: number;
    writeOperationsPerSecond: number;
  };
  networkIO: {
    inboundBytesPerSecond: number;
    outboundBytesPerSecond: number;
    inboundPacketsPerSecond: number;
    outboundPacketsPerSecond: number;
  };
}

export interface ThroughputMetrics {
  requestsPerSecond: number;
  responseTimeMs: {
    average: number;
    p50: number;
    p95: number;
    p99: number;
  };
  errorRate: number;
  activeConnections: number;
}

export interface ContainerInfo {
  containerId?: string;
  containerName?: string;
  imageName?: string;
  imageTag?: string;
  hostName: string;
  platform: string;
  uptime: number; // seconds
}

export interface InfrastructureMetricsResponse {
  success: boolean;
  data?: InfrastructureMetrics;
  error?: string;
  message?: string;
}

export interface MetricsHistoryRequest {
  timeRange: '1h' | '6h' | '24h' | '7d' | '30d';
  interval: '1m' | '5m' | '15m' | '1h' | '1d';
  metrics?: string[]; // Optional filter for specific metrics
}

export interface MetricsHistoryResponse {
  success: boolean;
  data?: InfrastructureMetrics[];
  timeRange: string;
  interval: string;
  error?: string;
  message?: string;
}

export class InfrastructureMetricsBuilder {
  private metrics: Partial<InfrastructureMetrics> = {};

  setTimestamp(timestamp: Date): InfrastructureMetricsBuilder {
    this.metrics.timestamp = timestamp;
    return this;
  }

  setProcessorUsage(processorUsage: ProcessorMetrics): InfrastructureMetricsBuilder {
    this.metrics.processorUsage = processorUsage;
    return this;
  }

  setRamUsage(ramUsage: MemoryMetrics): InfrastructureMetricsBuilder {
    this.metrics.ramUsage = ramUsage;
    return this;
  }

  setIOPerformance(ioPerformance: IOMetrics): InfrastructureMetricsBuilder {
    this.metrics.ioPerformance = ioPerformance;
    return this;
  }

  setThroughput(throughput: ThroughputMetrics): InfrastructureMetricsBuilder {
    this.metrics.throughput = throughput;
    return this;
  }

  setContainerInfo(containerInfo: ContainerInfo): InfrastructureMetricsBuilder {
    this.metrics.containerInfo = containerInfo;
    return this;
  }

  build(): InfrastructureMetrics {
    if (!this.metrics.timestamp || !this.metrics.processorUsage || 
        !this.metrics.ramUsage || !this.metrics.ioPerformance || 
        !this.metrics.throughput || !this.metrics.containerInfo) {
      throw new Error('Infrastructure metrics must have all required fields');
    }

    return {
      timestamp: this.metrics.timestamp,
      processorUsage: this.metrics.processorUsage,
      ramUsage: this.metrics.ramUsage,
      ioPerformance: this.metrics.ioPerformance,
      throughput: this.metrics.throughput,
      containerInfo: this.metrics.containerInfo
    };
  }
}

export class MetricsUtils {
  static formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  static formatPercentage(value: number): string {
    return `${value.toFixed(1)}%`;
  }

  static formatDuration(seconds: number): string {
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

  static getHealthStatus(metrics: InfrastructureMetrics): 'healthy' | 'warning' | 'critical' {
    const cpuThreshold = 80;
    const memoryThreshold = 85;
    const diskThreshold = 90;
    const errorRateThreshold = 5;

    const isCritical = 
      metrics.processorUsage.cpuUsagePercent > 95 ||
      metrics.ramUsage.usagePercent > 95 ||
      metrics.ioPerformance.diskUsage.usagePercent > 95 ||
      metrics.throughput.errorRate > 10;

    const isWarning = 
      metrics.processorUsage.cpuUsagePercent > cpuThreshold ||
      metrics.ramUsage.usagePercent > memoryThreshold ||
      metrics.ioPerformance.diskUsage.usagePercent > diskThreshold ||
      metrics.throughput.errorRate > errorRateThreshold;

    if (isCritical) return 'critical';
    if (isWarning) return 'warning';
    return 'healthy';
  }
}