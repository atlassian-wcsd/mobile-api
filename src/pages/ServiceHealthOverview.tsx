import React, { useState, useEffect } from 'react';
import InfrastructureMetricsComponent from '../components/InfrastructureMetrics';
import { InfrastructureMetricsService } from '../services/InfrastructureMetricsService';

interface ServiceHealthOverviewProps {
  className?: string;
}

interface ServiceStatus {
  status: 'healthy' | 'warning' | 'critical' | 'unknown';
  message: string;
  lastChecked: Date;
}

export const ServiceHealthOverview: React.FC<ServiceHealthOverviewProps> = ({
  className = ''
}) => {
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus>({
    status: 'unknown',
    message: 'Checking service status...',
    lastChecked: new Date()
  });
  const [showAdvancedMetrics, setShowAdvancedMetrics] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState('');
  const [showFeedbackForm, setShowFeedbackForm] = useState(false);

  const metricsService = new InfrastructureMetricsService();

  useEffect(() => {
    checkServiceHealth();
  }, []);

  const checkServiceHealth = async () => {
    try {
      const isAvailable = await metricsService.validateService();
      
      if (isAvailable) {
        setServiceStatus({
          status: 'healthy',
          message: 'All systems operational',
          lastChecked: new Date()
        });
      } else {
        setServiceStatus({
          status: 'warning',
          message: 'Metrics service unavailable - showing demo data',
          lastChecked: new Date()
        });
      }
    } catch (error) {
      setServiceStatus({
        status: 'critical',
        message: 'Unable to determine service health',
        lastChecked: new Date()
      });
    }
  };

  const handleMetricsError = (error: string) => {
    setServiceStatus({
      status: 'critical',
      message: `Infrastructure monitoring error: ${error}`,
      lastChecked: new Date()
    });
  };

  const handleFeedbackSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (feedbackMessage.trim()) {
      // In a real implementation, this would send feedback to a backend service
      console.log('Feedback submitted:', feedbackMessage);
      alert('Thank you for your feedback! We will review your suggestions.');
      setFeedbackMessage('');
      setShowFeedbackForm(false);
    }
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'healthy': return '#10B981';
      case 'warning': return '#F59E0B';
      case 'critical': return '#EF4444';
      default: return '#6B7280';
    }
  };

  const getStatusIcon = (status: string): string => {
    switch (status) {
      case 'healthy': return '✅';
      case 'warning': return '⚠️';
      case 'critical': return '❌';
      default: return '❓';
    }
  };

  return (
    <div className={`service-health-overview ${className}`} style={{
      maxWidth: '1200px',
      margin: '0 auto',
      padding: '20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      {/* Page Header */}
      <div style={{
        marginBottom: '32px',
        textAlign: 'center'
      }}>
        <h1 style={{
          margin: '0 0 8px 0',
          fontSize: '32px',
          fontWeight: '700',
          color: '#111827'
        }}>
          Service Health Overview
        </h1>
        <p style={{
          margin: '0',
          fontSize: '16px',
          color: '#6B7280'
        }}>
          Real-time monitoring of infrastructure performance and service health
        </p>
      </div>

      {/* Service Status Banner */}
      <div style={{
        marginBottom: '24px',
        padding: '16px 20px',
        backgroundColor: serviceStatus.status === 'healthy' ? '#ECFDF5' : 
                         serviceStatus.status === 'warning' ? '#FFFBEB' : '#FEF2F2',
        border: `1px solid ${serviceStatus.status === 'healthy' ? '#D1FAE5' : 
                              serviceStatus.status === 'warning' ? '#FDE68A' : '#FECACA'}`,
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '20px' }}>
            {getStatusIcon(serviceStatus.status)}
          </span>
          <div>
            <div style={{
              fontSize: '16px',
              fontWeight: '600',
              color: getStatusColor(serviceStatus.status),
              textTransform: 'capitalize'
            }}>
              Service Status: {serviceStatus.status}
            </div>
            <div style={{
              fontSize: '14px',
              color: '#6B7280',
              marginTop: '2px'
            }}>
              {serviceStatus.message}
            </div>
          </div>
        </div>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
        }}>
          <span style={{
            fontSize: '12px',
            color: '#6B7280'
          }}>
            Last checked: {serviceStatus.lastChecked.toLocaleTimeString()}
          </span>
          <button
            onClick={checkServiceHealth}
            style={{
              padding: '6px 12px',
              backgroundColor: '#3B82F6',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Quick Actions */}
      <div style={{
        marginBottom: '24px',
        display: 'flex',
        gap: '12px',
        flexWrap: 'wrap'
      }}>
        <button
          onClick={() => setShowAdvancedMetrics(!showAdvancedMetrics)}
          style={{
            padding: '8px 16px',
            backgroundColor: showAdvancedMetrics ? '#3B82F6' : '#F3F4F6',
            color: showAdvancedMetrics ? 'white' : '#374151',
            border: '1px solid #D1D5DB',
            borderRadius: '6px',
            fontSize: '14px',
            cursor: 'pointer'
          }}
        >
          {showAdvancedMetrics ? 'Hide' : 'Show'} Advanced Metrics
        </button>
        <button
          onClick={() => setShowFeedbackForm(!showFeedbackForm)}
          style={{
            padding: '8px 16px',
            backgroundColor: '#F3F4F6',
            color: '#374151',
            border: '1px solid #D1D5DB',
            borderRadius: '6px',
            fontSize: '14px',
            cursor: 'pointer'
          }}
        >
          💬 Provide Feedback
        </button>
      </div>

      {/* Infrastructure Metrics */}
      <InfrastructureMetricsComponent
        refreshInterval={30000}
        showHistory={showAdvancedMetrics}
        onError={handleMetricsError}
        className="main-metrics"
      />

      {/* Advanced Metrics Section */}
      {showAdvancedMetrics && (
        <div style={{
          marginTop: '24px',
          padding: '20px',
          backgroundColor: '#F9FAFB',
          border: '1px solid #E5E7EB',
          borderRadius: '8px'
        }}>
          <h3 style={{
            margin: '0 0 16px 0',
            fontSize: '18px',
            fontWeight: '600',
            color: '#111827'
          }}>
            Advanced Monitoring
          </h3>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '16px'
          }}>
            <div style={{
              padding: '16px',
              backgroundColor: 'white',
              borderRadius: '6px',
              border: '1px solid #E5E7EB'
            }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#374151' }}>
                📊 Historical Trends
              </h4>
              <p style={{ margin: '0', fontSize: '12px', color: '#6B7280' }}>
                View performance trends over time to identify patterns and potential issues.
              </p>
            </div>
            <div style={{
              padding: '16px',
              backgroundColor: 'white',
              borderRadius: '6px',
              border: '1px solid #E5E7EB'
            }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#374151' }}>
                🔔 Alert Configuration
              </h4>
              <p style={{ margin: '0', fontSize: '12px', color: '#6B7280' }}>
                Set up custom alerts for critical thresholds and performance degradation.
              </p>
            </div>
            <div style={{
              padding: '16px',
              backgroundColor: 'white',
              borderRadius: '6px',
              border: '1px solid #E5E7EB'
            }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#374151' }}>
                📈 Performance Analytics
              </h4>
              <p style={{ margin: '0', fontSize: '12px', color: '#6B7280' }}>
                Detailed analytics and insights for capacity planning and optimization.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Feedback Form */}
      {showFeedbackForm && (
        <div style={{
          marginTop: '24px',
          padding: '20px',
          backgroundColor: '#FFFFFF',
          border: '1px solid #E5E7EB',
          borderRadius: '8px'
        }}>
          <h3 style={{
            margin: '0 0 16px 0',
            fontSize: '18px',
            fontWeight: '600',
            color: '#111827'
          }}>
            Help Us Improve
          </h3>
          <form onSubmit={handleFeedbackSubmit}>
            <textarea
              value={feedbackMessage}
              onChange={(e) => setFeedbackMessage(e.target.value)}
              placeholder="Share your feedback about the service health overview. What additional metrics or features would be helpful?"
              style={{
                width: '100%',
                minHeight: '100px',
                padding: '12px',
                border: '1px solid #D1D5DB',
                borderRadius: '6px',
                fontSize: '14px',
                fontFamily: 'inherit',
                resize: 'vertical'
              }}
            />
            <div style={{
              marginTop: '12px',
              display: 'flex',
              gap: '8px'
            }}>
              <button
                type="submit"
                disabled={!feedbackMessage.trim()}
                style={{
                  padding: '8px 16px',
                  backgroundColor: feedbackMessage.trim() ? '#3B82F6' : '#9CA3AF',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  fontSize: '14px',
                  cursor: feedbackMessage.trim() ? 'pointer' : 'not-allowed'
                }}
              >
                Submit Feedback
              </button>
              <button
                type="button"
                onClick={() => setShowFeedbackForm(false)}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#F3F4F6',
                  color: '#374151',
                  border: '1px solid #D1D5DB',
                  borderRadius: '4px',
                  fontSize: '14px',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Footer Information */}
      <div style={{
        marginTop: '32px',
        padding: '16px',
        backgroundColor: '#F9FAFB',
        borderRadius: '6px',
        textAlign: 'center',
        fontSize: '12px',
        color: '#6B7280'
      }}>
        <p style={{ margin: '0 0 8px 0' }}>
          Infrastructure metrics are updated every 30 seconds. 
          For real-time alerts and detailed analytics, contact your operations team.
        </p>
        <p style={{ margin: '0' }}>
          Need help? Check the <a href="#" style={{ color: '#3B82F6' }}>monitoring documentation</a> or 
          <a href="#" style={{ color: '#3B82F6', marginLeft: '4px' }}>contact support</a>.
        </p>
      </div>
    </div>
  );
};

export default ServiceHealthOverview;