import React, { useState, useEffect } from 'react';
import InfrastructureMetricsPanel from '../components/InfrastructureMetrics/InfrastructureMetricsPanel';
import { InfrastructureMetricsService } from '../services/InfrastructureMetricsService';

interface ServiceHealthOverviewProps {
  serviceName?: string;
  autoRefresh?: boolean;
  refreshInterval?: number;
  className?: string;
}

export const ServiceHealthOverview: React.FC<ServiceHealthOverviewProps> = ({
  serviceName = 'Signature Application',
  autoRefresh = true,
  refreshInterval = 30000,
  className = ''
}) => {
  const [serviceHealthy, setServiceHealthy] = useState<boolean | null>(null);
  const [lastHealthCheck, setLastHealthCheck] = useState<Date | null>(null);

  const metricsService = new InfrastructureMetricsService();

  // Perform health check
  useEffect(() => {
    const performHealthCheck = async () => {
      try {
        const isHealthy = await metricsService.healthCheck();
        setServiceHealthy(isHealthy);
        setLastHealthCheck(new Date());
      } catch (error) {
        console.error('Health check failed:', error);
        setServiceHealthy(false);
        setLastHealthCheck(new Date());
      }
    };

    performHealthCheck();

    // Set up periodic health checks
    const healthCheckInterval = setInterval(performHealthCheck, 60000); // Every minute

    return () => {
      clearInterval(healthCheckInterval);
    };
  }, []);

  const pageStyles = {
    container: {
      minHeight: '100vh',
      backgroundColor: '#f5f5f5',
      padding: '20px'
    } as React.CSSProperties,

    header: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '24px',
      marginBottom: '20px',
      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
      border: '1px solid #e9ecef'
    } as React.CSSProperties,

    title: {
      fontSize: '32px',
      fontWeight: '700',
      color: '#212529',
      margin: '0 0 16px 0'
    } as React.CSSProperties,

    subtitle: {
      fontSize: '16px',
      color: '#6c757d',
      margin: '0 0 20px 0'
    } as React.CSSProperties,

    healthStatus: {
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      padding: '16px',
      borderRadius: '6px',
      fontSize: '16px',
      fontWeight: '500'
    } as React.CSSProperties,

    healthStatusHealthy: {
      backgroundColor: '#d4edda',
      color: '#155724',
      border: '1px solid #c3e6cb'
    } as React.CSSProperties,

    healthStatusUnhealthy: {
      backgroundColor: '#f8d7da',
      color: '#721c24',
      border: '1px solid #f5c6cb'
    } as React.CSSProperties,

    healthStatusUnknown: {
      backgroundColor: '#e2e3e5',
      color: '#383d41',
      border: '1px solid #d6d8db'
    } as React.CSSProperties,

    statusIndicator: {
      width: '16px',
      height: '16px',
      borderRadius: '50%'
    } as React.CSSProperties,

    statusHealthy: {
      backgroundColor: '#28a745'
    } as React.CSSProperties,

    statusUnhealthy: {
      backgroundColor: '#dc3545'
    } as React.CSSProperties,

    statusUnknown: {
      backgroundColor: '#6c757d'
    } as React.CSSProperties,

    lastChecked: {
      fontSize: '14px',
      color: '#6c757d',
      marginTop: '8px'
    } as React.CSSProperties,

    content: {
      maxWidth: '1400px',
      margin: '0 auto'
    } as React.CSSProperties,

    navigation: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '16px 24px',
      marginBottom: '20px',
      boxShadow: '0 1px 4px rgba(0, 0, 0, 0.1)',
      border: '1px solid #e9ecef'
    } as React.CSSProperties,

    navList: {
      display: 'flex',
      gap: '24px',
      margin: 0,
      padding: 0,
      listStyle: 'none'
    } as React.CSSProperties,

    navItem: {
      fontSize: '14px',
      fontWeight: '500'
    } as React.CSSProperties,

    navLink: {
      color: '#007bff',
      textDecoration: 'none',
      padding: '8px 12px',
      borderRadius: '4px',
      transition: 'background-color 0.2s ease'
    } as React.CSSProperties,

    navLinkActive: {
      backgroundColor: '#e3f2fd',
      color: '#1976d2'
    } as React.CSSProperties,

    footer: {
      backgroundColor: '#ffffff',
      borderRadius: '8px',
      padding: '20px 24px',
      marginTop: '20px',
      boxShadow: '0 1px 4px rgba(0, 0, 0, 0.1)',
      border: '1px solid #e9ecef',
      textAlign: 'center'
    } as React.CSSProperties,

    footerText: {
      fontSize: '14px',
      color: '#6c757d',
      margin: 0
    } as React.CSSProperties,

    refreshInfo: {
      fontSize: '12px',
      color: '#6c757d',
      fontStyle: 'italic',
      marginTop: '8px'
    } as React.CSSProperties
  };

  const getHealthStatusStyle = () => {
    if (serviceHealthy === null) return pageStyles.healthStatusUnknown;
    return serviceHealthy ? pageStyles.healthStatusHealthy : pageStyles.healthStatusUnhealthy;
  };

  const getStatusIndicatorStyle = () => {
    if (serviceHealthy === null) return pageStyles.statusUnknown;
    return serviceHealthy ? pageStyles.statusHealthy : pageStyles.statusUnhealthy;
  };

  const getHealthStatusText = () => {
    if (serviceHealthy === null) return 'Health status unknown';
    return serviceHealthy ? 'Service is healthy' : 'Service is experiencing issues';
  };

  const getHealthIcon = () => {
    if (serviceHealthy === null) {
      return <QuestionIcon />;
    }
    return serviceHealthy ? <CheckIcon /> : <ErrorIcon />;
  };

  return (
    <div style={pageStyles.container} className={className}>
      <div style={pageStyles.content}>
        {/* Page Header */}
        <header style={pageStyles.header}>
          <h1 style={pageStyles.title}>{serviceName} - Service Health Overview</h1>
          <p style={pageStyles.subtitle}>
            Monitor real-time infrastructure performance metrics and service health status
          </p>
          
          {/* Service Health Status */}
          <div style={{...pageStyles.healthStatus, ...getHealthStatusStyle()}}>
            <div style={{...pageStyles.statusIndicator, ...getStatusIndicatorStyle()}}></div>
            {getHealthIcon()}
            <span>{getHealthStatusText()}</span>
          </div>
          
          {lastHealthCheck && (
            <div style={pageStyles.lastChecked}>
              Last health check: {lastHealthCheck.toLocaleString()}
            </div>
          )}
          
          {autoRefresh && (
            <div style={pageStyles.refreshInfo}>
              Auto-refreshing every {Math.round(refreshInterval / 1000)} seconds
            </div>
          )}
        </header>

        {/* Navigation */}
        <nav style={pageStyles.navigation}>
          <ul style={pageStyles.navList}>
            <li style={pageStyles.navItem}>
              <a 
                href="#infrastructure" 
                style={{...pageStyles.navLink, ...pageStyles.navLinkActive}}
              >
                Infrastructure Metrics
              </a>
            </li>
            <li style={pageStyles.navItem}>
              <a href="#logs" style={pageStyles.navLink}>
                Application Logs
              </a>
            </li>
            <li style={pageStyles.navItem}>
              <a href="#performance" style={pageStyles.navLink}>
                Performance History
              </a>
            </li>
            <li style={pageStyles.navItem}>
              <a href="#alerts" style={pageStyles.navLink}>
                Alert Configuration
              </a>
            </li>
          </ul>
        </nav>

        {/* Main Content - Infrastructure Metrics */}
        <main id="infrastructure">
          <InfrastructureMetricsPanel
            autoRefresh={autoRefresh}
            refreshInterval={refreshInterval}
            showFeedback={true}
          />
        </main>

        {/* Additional Information Sections */}
        <section style={pageStyles.navigation}>
          <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: '600', color: '#495057' }}>
            Quick Actions
          </h3>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <QuickActionButton 
              label="View Detailed Logs" 
              onClick={() => console.log('Navigate to logs')}
            />
            <QuickActionButton 
              label="Download Metrics Report" 
              onClick={() => console.log('Download report')}
            />
            <QuickActionButton 
              label="Configure Alerts" 
              onClick={() => console.log('Configure alerts')}
            />
            <QuickActionButton 
              label="Service Documentation" 
              onClick={() => console.log('Open documentation')}
            />
          </div>
        </section>

        {/* Footer */}
        <footer style={pageStyles.footer}>
          <p style={pageStyles.footerText}>
            Service Health Overview - Real-time infrastructure monitoring and performance metrics
          </p>
          <p style={pageStyles.footerText}>
            For technical support or questions about these metrics, please contact the operations team.
          </p>
        </footer>
      </div>
    </div>
  );
};

// Quick Action Button Component
const QuickActionButton: React.FC<{ label: string; onClick: () => void }> = ({ label, onClick }) => {
  const buttonStyle = {
    padding: '8px 16px',
    backgroundColor: '#007bff',
    color: '#ffffff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'background-color 0.2s ease'
  } as React.CSSProperties;

  return (
    <button 
      style={buttonStyle}
      onClick={onClick}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = '#0056b3';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = '#007bff';
      }}
    >
      {label}
    </button>
  );
};

// Icon Components
const CheckIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z"/>
  </svg>
);

const ErrorIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z"/>
  </svg>
);

const QuestionIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M13,13H11V11H13V13M13,9H11V7H13V9Z"/>
  </svg>
);

export default ServiceHealthOverview;