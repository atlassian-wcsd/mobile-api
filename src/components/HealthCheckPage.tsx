import React, { useState, useEffect } from 'react';
import { HealthCheckResponse } from '../models/HealthCheck';
import { HealthCheckService } from '../services/HealthCheckService';

/**
 * Health Check Page Component
 * Displays API health status and performance metrics
 */
export const HealthCheckPage: React.FC = () => {
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const healthCheckService = new HealthCheckService();

  // Fetch health data
  const fetchHealthData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await healthCheckService.getHealthStatus();
      setHealthData(data);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch health data');
      setHealthData(null);
    } finally {
      setLoading(false);
    }
  };

  // Initial fetch and auto-refresh setup
  useEffect(() => {
    fetchHealthData();

    let stopRefresh: (() => void) | null = null;
    
    if (autoRefresh) {
      stopRefresh = healthCheckService.startPeriodicHealthCheck(
        30000, // Refresh every 30 seconds
        (health, error) => {
          if (error) {
            setError(error.message);
            setHealthData(null);
          } else {
            setHealthData(health);
            setError(null);
          }
          setLastUpdated(new Date());
        }
      );
    }

    return () => {
      if (stopRefresh) {
        stopRefresh();
      }
    };
  }, [autoRefresh]);

  // Format timestamp
  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleString();
  };

  // Get status color
  const getStatusColor = (status: 'healthy' | 'unhealthy' | 'degraded'): string => {
    switch (status) {
      case 'healthy':
        return '#4caf50';
      case 'degraded':
        return '#ff9800';
      case 'unhealthy':
        return '#f44336';
      default:
        return '#9e9e9e';
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>API Health Check Dashboard</h1>
        <div style={styles.controls}>
          <button onClick={fetchHealthData} style={styles.button} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh Now'}
          </button>
          <label style={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              style={styles.checkbox}
            />
            Auto-refresh (30s)
          </label>
        </div>
        {lastUpdated && (
          <p style={styles.lastUpdated}>
            Last updated: {lastUpdated.toLocaleTimeString()}
          </p>
        )}
      </div>

      {error && (
        <div style={styles.errorBox}>
          <h3>Error</h3>
          <p>{error}</p>
        </div>
      )}

      {healthData && (
        <div>
          {/* Overall Status */}
          <div style={{
            ...styles.card,
            borderLeft: `5px solid ${getStatusColor(healthData.status)}`
          }}>
            <h2 style={styles.cardTitle}>Overall Status</h2>
            <div style={styles.statusBadge}>
              <span
                style={{
                  ...styles.statusIndicator,
                  backgroundColor: getStatusColor(healthData.status)
                }}
              />
              <span style={styles.statusText}>
                {healthData.status.toUpperCase()}
              </span>
            </div>
            <p style={styles.infoText}>Version: {healthData.version}</p>
            <p style={styles.infoText}>
              Timestamp: {formatTimestamp(healthData.timestamp)}
            </p>
          </div>

          {/* Performance Metrics */}
          <div style={styles.card}>
            <h2 style={styles.cardTitle}>Performance Metrics</h2>
            <div style={styles.metricsGrid}>
              <div style={styles.metricItem}>
                <p style={styles.metricLabel}>Average Response Time</p>
                <p style={styles.metricValue}>
                  {healthData.performance.averageResponseTimeMs.toFixed(2)} ms
                </p>
              </div>
              <div style={styles.metricItem}>
                <p style={styles.metricLabel}>Uptime Status</p>
                <p style={styles.metricValue}>
                  {healthData.performance.uptime}
                </p>
              </div>
            </div>
          </div>

          {/* Service Status */}
          <div style={styles.card}>
            <h2 style={styles.cardTitle}>Service Health</h2>
            <div style={styles.servicesGrid}>
              {/* S3 Service */}
              <div style={styles.serviceCard}>
                <div style={styles.serviceHeader}>
                  <h3 style={styles.serviceName}>Amazon S3</h3>
                  <span
                    style={{
                      ...styles.statusIndicator,
                      backgroundColor: getStatusColor(healthData.services.s3.status)
                    }}
                  />
                </div>
                <p style={styles.serviceStatus}>
                  Status: {healthData.services.s3.status.toUpperCase()}
                </p>
                <p style={styles.serviceMetric}>
                  Response Time: {healthData.services.s3.responseTimeMs.toFixed(2)} ms
                </p>
                {healthData.services.s3.message && (
                  <p style={styles.serviceMessage}>
                    {healthData.services.s3.message}
                  </p>
                )}
              </div>

              {/* DynamoDB Service */}
              <div style={styles.serviceCard}>
                <div style={styles.serviceHeader}>
                  <h3 style={styles.serviceName}>Amazon DynamoDB</h3>
                  <span
                    style={{
                      ...styles.statusIndicator,
                      backgroundColor: getStatusColor(healthData.services.dynamodb.status)
                    }}
                  />
                </div>
                <p style={styles.serviceStatus}>
                  Status: {healthData.services.dynamodb.status.toUpperCase()}
                </p>
                <p style={styles.serviceMetric}>
                  Response Time: {healthData.services.dynamodb.responseTimeMs.toFixed(2)} ms
                </p>
                {healthData.services.dynamodb.message && (
                  <p style={styles.serviceMessage}>
                    {healthData.services.dynamodb.message}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {loading && !healthData && (
        <div style={styles.loadingContainer}>
          <div style={styles.spinner} />
          <p>Loading health data...</p>
        </div>
      )}
    </div>
  );
};

// Styles
const styles: { [key: string]: React.CSSProperties } = {
  container: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '20px',
    fontFamily: 'Arial, sans-serif',
    backgroundColor: '#f5f5f5',
  },
  header: {
    marginBottom: '30px',
    backgroundColor: 'white',
    padding: '20px',
    borderRadius: '8px',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
  },
  title: {
    fontSize: '28px',
    marginBottom: '15px',
    color: '#333',
  },
  controls: {
    display: 'flex',
    gap: '15px',
    alignItems: 'center',
    marginBottom: '10px',
  },
  button: {
    padding: '10px 20px',
    fontSize: '14px',
    backgroundColor: '#2196f3',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    cursor: 'pointer',
  },
  checkbox: {
    cursor: 'pointer',
  },
  lastUpdated: {
    fontSize: '12px',
    color: '#666',
    marginTop: '10px',
  },
  errorBox: {
    backgroundColor: '#ffebee',
    padding: '20px',
    borderRadius: '8px',
    marginBottom: '20px',
    borderLeft: '5px solid #f44336',
  },
  card: {
    backgroundColor: 'white',
    padding: '20px',
    borderRadius: '8px',
    marginBottom: '20px',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
  },
  cardTitle: {
    fontSize: '20px',
    marginBottom: '15px',
    color: '#333',
  },
  statusBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    marginBottom: '15px',
  },
  statusIndicator: {
    width: '16px',
    height: '16px',
    borderRadius: '50%',
    display: 'inline-block',
  },
  statusText: {
    fontSize: '18px',
    fontWeight: 'bold',
  },
  infoText: {
    margin: '5px 0',
    color: '#666',
  },
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '20px',
  },
  metricItem: {
    padding: '15px',
    backgroundColor: '#f9f9f9',
    borderRadius: '4px',
  },
  metricLabel: {
    fontSize: '14px',
    color: '#666',
    marginBottom: '5px',
  },
  metricValue: {
    fontSize: '24px',
    fontWeight: 'bold',
    color: '#333',
  },
  servicesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
    gap: '20px',
  },
  serviceCard: {
    padding: '15px',
    backgroundColor: '#f9f9f9',
    borderRadius: '4px',
    border: '1px solid #e0e0e0',
  },
  serviceHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '10px',
  },
  serviceName: {
    fontSize: '16px',
    margin: 0,
  },
  serviceStatus: {
    fontSize: '14px',
    fontWeight: 'bold',
    margin: '5px 0',
  },
  serviceMetric: {
    fontSize: '14px',
    color: '#666',
    margin: '5px 0',
  },
  serviceMessage: {
    fontSize: '12px',
    color: '#f44336',
    marginTop: '10px',
    fontStyle: 'italic',
  },
  loadingContainer: {
    textAlign: 'center',
    padding: '40px',
  },
  spinner: {
    width: '40px',
    height: '40px',
    margin: '0 auto 20px',
    border: '4px solid #f3f3f3',
    borderTop: '4px solid #2196f3',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  },
};

export default HealthCheckPage;
