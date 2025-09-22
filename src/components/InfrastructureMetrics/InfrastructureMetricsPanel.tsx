import React, { useState, useEffect, useCallback } from 'react';
import { InfrastructureMetricsService, MetricsUtils } from '../../services/InfrastructureMetricsService';
import {
  InfrastructureMetrics,
  MetricsAlert,
  MetricsFeedback,
  MetricsConfiguration
} from '../../types/InfrastructureMetrics';
import { styles } from './InfrastructureMetrics.styles';

interface InfrastructureMetricsPanelProps {
  autoRefresh?: boolean;
  refreshInterval?: number;
  showFeedback?: boolean;
  className?: string;
}

export const InfrastructureMetricsPanel: React.FC<InfrastructureMetricsPanelProps> = ({
  autoRefresh = true,
  refreshInterval = 30000,
  showFeedback = true,
  className = ''
}) => {
  const [metrics, setMetrics] = useState<InfrastructureMetrics | null>(null);
  const [alerts, setAlerts] = useState<MetricsAlert[]>([]);
  const [configuration, setConfiguration] = useState<MetricsConfiguration | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [feedbackVisible, setFeedbackVisible] = useState(false);
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false);

  const metricsService = new InfrastructureMetricsService();

  // Fetch metrics data
  const fetchMetrics = useCallback(async () => {
    try {
      setError(null);
      const [metricsData, alertsData, configData] = await Promise.all([
        metricsService.getCurrentMetrics(),
        metricsService.getActiveAlerts(),
        metricsService.getConfiguration()
      ]);

      setMetrics(metricsData);
      setAlerts(alertsData);
      setConfiguration(configData);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
      console.error('Error fetching metrics:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initialize and set up auto-refresh
  useEffect(() => {
    fetchMetrics();

    if (autoRefresh) {
      metricsService.startAutoRefresh((newMetrics) => {
        setMetrics(newMetrics);
        setLastUpdated(new Date());
      }, refreshInterval);

      return () => {
        metricsService.stopAutoRefresh();
      };
    }
  }, [fetchMetrics, autoRefresh, refreshInterval]);

  // Handle feedback submission
  const handleFeedbackSubmit = async (feedbackData: Omit<MetricsFeedback, 'timestamp'>) => {
    setFeedbackSubmitting(true);
    try {
      await metricsService.submitFeedback(feedbackData);
      setFeedbackVisible(false);
      // Could show a success message here
    } catch (err) {
      console.error('Error submitting feedback:', err);
      // Could show an error message here
    } finally {
      setFeedbackSubmitting(false);
    }
  };

  // Render loading state
  if (loading) {
    return (
      <div style={styles.loadingContainer}>
        <div style={styles.loadingSpinner}></div>
        <span>Loading infrastructure metrics...</span>
      </div>
    );
  }

  // Render error state
  if (error) {
    return (
      <div style={styles.errorContainer}>
        <div style={styles.errorMessage}>Unable to load infrastructure metrics</div>
        <div style={styles.errorDetails}>{error}</div>
        <button 
          onClick={fetchMetrics}
          style={{
            ...styles.feedbackButton,
            marginTop: '16px'
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!metrics) {
    return null;
  }

  return (
    <div style={styles.metricsContainer} className={`metrics-fade-in ${className}`}>
      {/* Header */}
      <div style={styles.metricsHeader}>
        <h2 style={styles.metricsTitle}>Infrastructure Performance</h2>
        <div style={styles.lastUpdated}>
          Last updated: {lastUpdated?.toLocaleTimeString() || 'Unknown'}
        </div>
      </div>

      {/* Alerts Section */}
      {alerts.length > 0 && (
        <AlertsSection alerts={alerts} />
      )}

      {/* Metrics Grid */}
      <div style={styles.metricsGrid}>
        <CPUMetricCard cpu={metrics.cpu} />
        <MemoryMetricCard memory={metrics.memory} />
        <IOMetricCard io={metrics.io} />
        <NetworkMetricCard network={metrics.network} />
      </div>

      {/* Service Status and Uptime */}
      <ServiceStatusCard 
        status={metrics.serviceStatus}
        uptime={metrics.uptime}
      />

      {/* Feedback Section */}
      {showFeedback && (
        <FeedbackSection
          visible={feedbackVisible}
          onToggle={() => setFeedbackVisible(!feedbackVisible)}
          onSubmit={handleFeedbackSubmit}
          submitting={feedbackSubmitting}
        />
      )}
    </div>
  );
};

// CPU Metrics Card Component
const CPUMetricCard: React.FC<{ cpu: InfrastructureMetrics['cpu'] }> = ({ cpu }) => {
  const statusColor = MetricsUtils.getStatusColor(cpu.usage, 80);

  return (
    <div style={styles.metricCard} className="metrics-card-hover">
      <div style={styles.metricCardHeader}>
        <h3 style={styles.metricTitle}>CPU Usage</h3>
        <CPUIcon style={styles.metricIcon} />
      </div>
      
      <div style={styles.metricValue}>
        {MetricsUtils.formatPercentage(cpu.usage)}
      </div>
      
      <div style={styles.progressBar}>
        <div 
          style={{
            ...styles.progressFill,
            width: `${cpu.usage}%`,
            backgroundColor: statusColor
          }}
        />
      </div>

      <div style={styles.metricDetails}>
        <div style={styles.metricDetailRow}>
          <span>Cores:</span>
          <span>{cpu.cores}</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Load (1m):</span>
          <span>{cpu.loadAverage.oneMinute.toFixed(2)}</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Load (5m):</span>
          <span>{cpu.loadAverage.fiveMinutes.toFixed(2)}</span>
        </div>
      </div>
    </div>
  );
};

// Memory Metrics Card Component
const MemoryMetricCard: React.FC<{ memory: InfrastructureMetrics['memory'] }> = ({ memory }) => {
  const statusColor = MetricsUtils.getStatusColor(memory.usage, 85);

  return (
    <div style={styles.metricCard} className="metrics-card-hover">
      <div style={styles.metricCardHeader}>
        <h3 style={styles.metricTitle}>Memory Usage</h3>
        <MemoryIcon style={styles.metricIcon} />
      </div>
      
      <div style={styles.metricValue}>
        {MetricsUtils.formatPercentage(memory.usage)}
      </div>
      
      <div style={styles.progressBar}>
        <div 
          style={{
            ...styles.progressFill,
            width: `${memory.usage}%`,
            backgroundColor: statusColor
          }}
        />
      </div>

      <div style={styles.metricDetails}>
        <div style={styles.metricDetailRow}>
          <span>Used:</span>
          <span>{MetricsUtils.formatBytes(memory.used * 1024 * 1024)}</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Total:</span>
          <span>{MetricsUtils.formatBytes(memory.total * 1024 * 1024)}</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Available:</span>
          <span>{MetricsUtils.formatBytes(memory.available * 1024 * 1024)}</span>
        </div>
      </div>
    </div>
  );
};

// IO Metrics Card Component
const IOMetricCard: React.FC<{ io: InfrastructureMetrics['io'] }> = ({ io }) => {
  const statusColor = MetricsUtils.getStatusColor(io.diskUsage, 90);

  return (
    <div style={styles.metricCard} className="metrics-card-hover">
      <div style={styles.metricCardHeader}>
        <h3 style={styles.metricTitle}>I/O Performance</h3>
        <IOIcon style={styles.metricIcon} />
      </div>
      
      <div style={styles.metricValue}>
        {MetricsUtils.formatPercentage(io.diskUsage)}
        <span style={styles.metricUnit}> disk</span>
      </div>
      
      <div style={styles.progressBar}>
        <div 
          style={{
            ...styles.progressFill,
            width: `${io.diskUsage}%`,
            backgroundColor: statusColor
          }}
        />
      </div>

      <div style={styles.metricDetails}>
        <div style={styles.metricDetailRow}>
          <span>Read:</span>
          <span>{io.readThroughput.toFixed(1)} MB/s</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Write:</span>
          <span>{io.writeThroughput.toFixed(1)} MB/s</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>IOPS:</span>
          <span>{io.readIOPS + io.writeIOPS}</span>
        </div>
      </div>
    </div>
  );
};

// Network Metrics Card Component
const NetworkMetricCard: React.FC<{ network: InfrastructureMetrics['network'] }> = ({ network }) => {
  const totalThroughput = network.inboundThroughput + network.outboundThroughput;

  return (
    <div style={styles.metricCard} className="metrics-card-hover">
      <div style={styles.metricCardHeader}>
        <h3 style={styles.metricTitle}>Network Throughput</h3>
        <NetworkIcon style={styles.metricIcon} />
      </div>
      
      <div style={styles.metricValue}>
        {totalThroughput.toFixed(1)}
        <span style={styles.metricUnit}> MB/s</span>
      </div>

      <div style={styles.metricDetails}>
        <div style={styles.metricDetailRow}>
          <span>Inbound:</span>
          <span>{network.inboundThroughput.toFixed(1)} MB/s</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Outbound:</span>
          <span>{network.outboundThroughput.toFixed(1)} MB/s</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Connections:</span>
          <span>{network.connectionsActive}</span>
        </div>
        <div style={styles.metricDetailRow}>
          <span>Packets/s:</span>
          <span>{network.packetsPerSecond}</span>
        </div>
      </div>
    </div>
  );
};

// Service Status Card Component
const ServiceStatusCard: React.FC<{ status: InfrastructureMetrics['serviceStatus'], uptime: number }> = ({ status, uptime }) => {
  const getStatusStyle = (status: string) => {
    switch (status) {
      case 'healthy': return styles.statusHealthy;
      case 'warning': return styles.statusWarning;
      case 'critical': return styles.statusCritical;
      default: return styles.statusUnknown;
    }
  };

  return (
    <div style={styles.metricCard} className="metrics-card-hover">
      <div style={styles.metricCardHeader}>
        <h3 style={styles.metricTitle}>Service Status</h3>
        <StatusIcon style={styles.metricIcon} />
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ ...styles.statusIndicator, ...getStatusStyle(status) }}></div>
        <span style={{ fontSize: '18px', fontWeight: '600', textTransform: 'capitalize' }}>
          {status}
        </span>
      </div>

      <div style={styles.metricDetails}>
        <div style={styles.metricDetailRow}>
          <span>Uptime:</span>
          <span>{MetricsUtils.formatUptime(uptime)}</span>
        </div>
      </div>
    </div>
  );
};

// Alerts Section Component
const AlertsSection: React.FC<{ alerts: MetricsAlert[] }> = ({ alerts }) => {
  return (
    <div style={styles.alertsSection}>
      <div style={styles.alertsHeader}>
        <AlertIcon style={{ width: '20px', height: '20px', marginRight: '8px' }} />
        Active Alerts ({alerts.length})
      </div>
      
      {alerts.map((alert) => (
        <div 
          key={alert.id}
          style={{
            ...styles.alertItem,
            ...(alert.severity === 'critical' ? styles.alertCritical : styles.alertWarning)
          }}
        >
          <div style={styles.alertIcon}>
            {alert.severity === 'critical' ? <CriticalIcon /> : <WarningIcon />}
          </div>
          <div style={styles.alertContent}>
            <div style={styles.alertMessage}>{alert.message}</div>
            <div style={styles.alertTimestamp}>
              {alert.timestamp.toLocaleString()}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

// Feedback Section Component
const FeedbackSection: React.FC<{
  visible: boolean;
  onToggle: () => void;
  onSubmit: (feedback: Omit<MetricsFeedback, 'timestamp'>) => void;
  submitting: boolean;
}> = ({ visible, onToggle, onSubmit, submitting }) => {
  const [rating, setRating] = useState<1 | 2 | 3 | 4 | 5>(5);
  const [comment, setComment] = useState('');
  const [category, setCategory] = useState<MetricsFeedback['category']>('display');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ rating, comment, category });
    setComment('');
    setRating(5);
    setCategory('display');
  };

  return (
    <div style={styles.feedbackSection}>
      <div style={styles.feedbackHeader}>
        <button 
          onClick={onToggle}
          style={{
            ...styles.feedbackButton,
            marginBottom: visible ? '16px' : '0'
          }}
        >
          {visible ? 'Hide Feedback' : 'Provide Feedback'}
        </button>
      </div>

      {visible && (
        <form onSubmit={handleSubmit} style={styles.feedbackForm}>
          <div style={styles.feedbackRow}>
            <label style={styles.feedbackLabel}>Rating:</label>
            <select 
              value={rating} 
              onChange={(e) => setRating(Number(e.target.value) as 1 | 2 | 3 | 4 | 5)}
              style={styles.feedbackInput}
            >
              <option value={5}>5 - Excellent</option>
              <option value={4}>4 - Good</option>
              <option value={3}>3 - Average</option>
              <option value={2}>2 - Poor</option>
              <option value={1}>1 - Very Poor</option>
            </select>
          </div>

          <div style={styles.feedbackRow}>
            <label style={styles.feedbackLabel}>Category:</label>
            <select 
              value={category} 
              onChange={(e) => setCategory(e.target.value as MetricsFeedback['category'])}
              style={styles.feedbackInput}
            >
              <option value="display">Display</option>
              <option value="accuracy">Accuracy</option>
              <option value="performance">Performance</option>
              <option value="feature_request">Feature Request</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div style={styles.feedbackRow}>
            <label style={styles.feedbackLabel}>Comment:</label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Please share your feedback about the infrastructure metrics display..."
              style={styles.feedbackTextarea}
              required
            />
          </div>

          <button 
            type="submit" 
            disabled={submitting || !comment.trim()}
            style={{
              ...styles.feedbackButton,
              ...(submitting || !comment.trim() ? { backgroundColor: '#6c757d', cursor: 'not-allowed' } : {})
            }}
          >
            {submitting ? 'Submitting...' : 'Submit Feedback'}
          </button>
        </form>
      )}
    </div>
  );
};

// Icon Components
const CPUIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 3V5H7V3H5V7H3V9H5V15H3V17H5V21H7V19H9V21H11V19H13V21H15V19H17V21H19V17H21V15H19V9H21V7H19V3H17V5H15V3H13V5H11V3H9ZM7 7H17V17H7V7ZM9 9V15H15V9H9Z"/>
  </svg>
);

const MemoryIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M17,7H22V9H24V15H22V17H17V19H15V17H9V19H7V17H2V15H0V9H2V7H7V5H9V7H15V5H17V7M4,9V15H20V9H4M6,11H8V13H6V11M10,11H12V13H10V11M14,11H16V13H14V11M18,11H20V13H18V11Z"/>
  </svg>
);

const IOIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M6,2H18A2,2 0 0,1 20,4V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V4A2,2 0 0,1 6,2M12,4A6,6 0 0,0 6,10C6,13.31 8.69,16 12.1,16L11.22,13.77C10.95,13.29 11.11,12.68 11.59,12.4L12.45,11.9C12.93,11.63 13.54,11.79 13.82,12.27L15.74,14.69C17.12,13.59 18,11.9 18,10A6,6 0 0,0 12,4M12,9A1,1 0 0,1 13,10A1,1 0 0,1 12,11A1,1 0 0,1 11,10A1,1 0 0,1 12,9M7,18A1,1 0 0,0 8,19A1,1 0 0,0 9,18A1,1 0 0,0 8,17A1,1 0 0,0 7,18M12.09,13.27L14.58,19.58L17.17,18.08L12.95,12.77L12.09,13.27Z"/>
  </svg>
);

const NetworkIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M4,1C2.89,1 2,1.89 2,3V7C2,8.11 2.89,9 4,9H1V11H13V9H10C11.11,9 12,8.11 12,7V3C12,1.89 11.11,1 10,1H4M4,3H10V7H4V3M3,13V18L3,19H21V18V13H19V17H5V13H3M7,21V23H9V21H7M11,21V23H13V21H11M15,21V23H17V21H15Z"/>
  </svg>
);

const StatusIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z"/>
  </svg>
);

const AlertIcon: React.FC<{ style?: React.CSSProperties }> = ({ style }) => (
  <svg style={style} viewBox="0 0 24 24" fill="currentColor">
    <path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/>
  </svg>
);

const WarningIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/>
  </svg>
);

const CriticalIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z"/>
  </svg>
);

export default InfrastructureMetricsPanel;