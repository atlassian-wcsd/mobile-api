import React, { useState, useEffect, useCallback } from 'react';
import { InfrastructureMetrics, MetricsUtils } from '../models/InfrastructureMetrics';
import { InfrastructureMetricsService, InfrastructureMetricsUtils } from '../services/InfrastructureMetricsService';

interface InfrastructureMetricsProps {
  refreshInterval?: number; // in milliseconds
  showHistory?: boolean;
  className?: string;
  onError?: (error: string) => void;
}

export const InfrastructureMetricsComponent: React.FC<InfrastructureMetricsProps> = ({
  refreshInterval = 30000, // 30 seconds default
  showHistory = false,
  className = '',
  onError
}) => {
  const [metrics, setMetrics] = useState<InfrastructureMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isServiceAvailable, setIsServiceAvailable] = useState(true);

  const metricsService = new InfrastructureMetricsService();

  const handleError = useCallback((errorMessage: string) => {
    setError(errorMessage);
    setIsLoading(false);
    if (onError) {
      onError(errorMessage);
    }
  }, [onError]);

  const fetchMetrics = useCallback(async () => {
    try {
      setError(null);
      
      // Check if service is available
      const serviceAvailable = await metricsService.validateService();
      setIsServiceAvailable(serviceAvailable);
      
      let metricsData: InfrastructureMetrics;
      
      if (serviceAvailable) {
        metricsData = await metricsService.getCurrentMetrics();
      } else {
        // Use mock data for development/demo purposes
        metricsData = InfrastructureMetricsUtils.generateMockMetrics();
      }
      
      // Calculate derived metrics
      metricsData = InfrastructureMetricsUtils.calculateDerivedMetrics(metricsData);
      
      setMetrics(metricsData);
      setLastUpdated(new Date());
      setIsLoading(false);
    } catch (error) {
      handleError(error instanceof Error ? error.message : 'Failed to fetch metrics');
    }
  }, [metricsService, handleError]);

  useEffect(() => {
    // Initial fetch
    fetchMetrics();

    // Set up polling for real-time updates
    const intervalId = setInterval(fetchMetrics, refreshInterval);

    // Cleanup
    return () => {
      clearInterval(intervalId);
    };
  }, [fetchMetrics, refreshInterval]);

  const getHealthStatusColor = (status: string): string => {
    switch (status) {
      case 'healthy': return '#10B981'; // green
      case 'warning': return '#F59E0B'; // yellow
      case 'critical': return '#EF4444'; // red
      default: return '#6B7280'; // gray
    }
  };

  const formatUptime = (seconds: number): string => {
    return MetricsUtils.formatDuration(seconds);
  };

  if (isLoading && !metrics) {
    return (
      <div className={`infrastructure-metrics ${className}`}>
        <div className="loading-container" style={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center', 
          padding: '40px',
          color: '#6B7280'
        }}>
          <div className="spinner" style={{
            width: '24px',
            height: '24px',
            border: '2px solid #E5E7EB',
            borderTop: '2px solid #3B82F6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            marginRight: '12px'
          }} />
          Loading infrastructure metrics...
        </div>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className={`infrastructure-metrics ${className}`}>
        <div className="error-container" style={{
          padding: '20px',
          backgroundColor: '#FEF2F2',
          border: '1px solid #FECACA',
          borderRadius: '8px',
          color: '#DC2626'
        }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: '16px', fontWeight: '600' }}>
            Failed to Load Infrastructure Metrics
          </h3>
          <p style={{ margin: '0', fontSize: '14px' }}>{error}</p>
          <button
            onClick={fetchMetrics}
            style={{
              marginTop: '12px',
              padding: '8px 16px',
              backgroundColor: '#DC2626',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '14px'
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!metrics) {
    return null;
  }

  const healthStatus = MetricsUtils.getHealthStatus(metrics);
  const healthColor = getHealthStatusColor(healthStatus);

  return (
    <div className={`infrastructure-metrics ${className}`} style={{
      backgroundColor: '#FFFFFF',
      border: '1px solid #E5E7EB',
      borderRadius: '8px',
      padding: '24px'
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '24px',
        borderBottom: '1px solid #E5E7EB',
        paddingBottom: '16px'
      }}>
        <h2 style={{
          margin: '0',
          fontSize: '20px',
          fontWeight: '600',
          color: '#111827'
        }}>
          Infrastructure Performance
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: healthColor
            }} />
            <span style={{
              fontSize: '14px',
              fontWeight: '500',
              color: healthColor,
              textTransform: 'capitalize'
            }}>
              {healthStatus}
            </span>
          </div>
          {!isServiceAvailable && (
            <span style={{
              fontSize: '12px',
              color: '#F59E0B',
              backgroundColor: '#FEF3C7',
              padding: '2px 8px',
              borderRadius: '4px'
            }}>
              Demo Mode
            </span>
          )}
          {lastUpdated && (
            <span style={{
              fontSize: '12px',
              color: '#6B7280'
            }}>
              Updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '20px'
      }}>
        {/* CPU Metrics */}
        <MetricCard
          title="Processor Usage"
          icon="🖥️"
          metrics={[
            {
              label: 'CPU Usage',
              value: MetricsUtils.formatPercentage(metrics.processorUsage.cpuUsagePercent),
              status: metrics.processorUsage.cpuUsagePercent > 80 ? 'warning' : 'normal'
            },
            {
              label: 'Load Average (1m)',
              value: metrics.processorUsage.loadAverage.oneMinute.toFixed(2),
              status: 'normal'
            },
            {
              label: 'Cores',
              value: metrics.processorUsage.coreCount.toString(),
              status: 'normal'
            }
          ]}
        />

        {/* Memory Metrics */}
        <MetricCard
          title="Memory Usage"
          icon="💾"
          metrics={[
            {
              label: 'RAM Usage',
              value: MetricsUtils.formatPercentage(metrics.ramUsage.usagePercent),
              status: metrics.ramUsage.usagePercent > 85 ? 'warning' : 'normal'
            },
            {
              label: 'Used Memory',
              value: `${(metrics.ramUsage.usedMemoryMB / 1024).toFixed(1)} GB`,
              status: 'normal'
            },
            {
              label: 'Total Memory',
              value: `${(metrics.ramUsage.totalMemoryMB / 1024).toFixed(1)} GB`,
              status: 'normal'
            }
          ]}
        />

        {/* Disk I/O Metrics */}
        <MetricCard
          title="Storage & I/O"
          icon="💿"
          metrics={[
            {
              label: 'Disk Usage',
              value: MetricsUtils.formatPercentage(metrics.ioPerformance.diskUsage.usagePercent),
              status: metrics.ioPerformance.diskUsage.usagePercent > 90 ? 'warning' : 'normal'
            },
            {
              label: 'Read Speed',
              value: MetricsUtils.formatBytes(metrics.ioPerformance.diskIO.readBytesPerSecond) + '/s',
              status: 'normal'
            },
            {
              label: 'Write Speed',
              value: MetricsUtils.formatBytes(metrics.ioPerformance.diskIO.writeBytesPerSecond) + '/s',
              status: 'normal'
            }
          ]}
        />

        {/* Network Throughput */}
        <MetricCard
          title="Network Throughput"
          icon="🌐"
          metrics={[
            {
              label: 'Requests/sec',
              value: metrics.throughput.requestsPerSecond.toFixed(0),
              status: 'normal'
            },
            {
              label: 'Response Time (avg)',
              value: `${metrics.throughput.responseTimeMs.average.toFixed(0)}ms`,
              status: metrics.throughput.responseTimeMs.average > 500 ? 'warning' : 'normal'
            },
            {
              label: 'Error Rate',
              value: MetricsUtils.formatPercentage(metrics.throughput.errorRate),
              status: metrics.throughput.errorRate > 5 ? 'warning' : 'normal'
            }
          ]}
        />
      </div>

      {/* Container Info */}
      <div style={{
        marginTop: '24px',
        padding: '16px',
        backgroundColor: '#F9FAFB',
        borderRadius: '6px',
        border: '1px solid #E5E7EB'
      }}>
        <h3 style={{
          margin: '0 0 12px 0',
          fontSize: '14px',
          fontWeight: '600',
          color: '#374151'
        }}>
          Container Information
        </h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
          fontSize: '12px',
          color: '#6B7280'
        }}>
          <div>
            <strong>Host:</strong> {metrics.containerInfo.hostName}
          </div>
          <div>
            <strong>Platform:</strong> {metrics.containerInfo.platform}
          </div>
          <div>
            <strong>Uptime:</strong> {formatUptime(metrics.containerInfo.uptime)}
          </div>
          {metrics.containerInfo.containerName && (
            <div>
              <strong>Container:</strong> {metrics.containerInfo.containerName}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

interface MetricCardProps {
  title: string;
  icon: string;
  metrics: Array<{
    label: string;
    value: string;
    status: 'normal' | 'warning' | 'critical';
  }>;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, icon, metrics }) => {
  return (
    <div style={{
      padding: '16px',
      backgroundColor: '#F9FAFB',
      border: '1px solid #E5E7EB',
      borderRadius: '6px'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        marginBottom: '12px'
      }}>
        <span style={{ fontSize: '18px', marginRight: '8px' }}>{icon}</span>
        <h3 style={{
          margin: '0',
          fontSize: '14px',
          fontWeight: '600',
          color: '#374151'
        }}>
          {title}
        </h3>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {metrics.map((metric, index) => (
          <div key={index} style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span style={{
              fontSize: '12px',
              color: '#6B7280'
            }}>
              {metric.label}
            </span>
            <span style={{
              fontSize: '14px',
              fontWeight: '600',
              color: metric.status === 'warning' ? '#F59E0B' : 
                     metric.status === 'critical' ? '#EF4444' : '#111827'
            }}>
              {metric.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default InfrastructureMetricsComponent;