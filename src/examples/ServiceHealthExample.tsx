import React from 'react';
import ServiceHealthOverview from '../pages/ServiceHealthOverview';
import InfrastructureMetricsPanel from '../components/InfrastructureMetrics/InfrastructureMetricsPanel';

/**
 * Example usage of the Service Health Overview components
 * 
 * This file demonstrates how to integrate the infrastructure metrics
 * functionality into your application.
 */

// Example 1: Full Service Health Overview Page
export const FullServiceHealthExample: React.FC = () => {
  return (
    <ServiceHealthOverview
      serviceName="My Application Service"
      autoRefresh={true}
      refreshInterval={30000} // 30 seconds
    />
  );
};

// Example 2: Standalone Infrastructure Metrics Panel
export const StandaloneMetricsExample: React.FC = () => {
  return (
    <div style={{ padding: '20px', backgroundColor: '#f5f5f5', minHeight: '100vh' }}>
      <h1 style={{ marginBottom: '20px', color: '#333' }}>
        Infrastructure Metrics Dashboard
      </h1>
      
      <InfrastructureMetricsPanel
        autoRefresh={true}
        refreshInterval={15000} // 15 seconds for more frequent updates
        showFeedback={true}
      />
    </div>
  );
};

// Example 3: Embedded Metrics Panel (without feedback)
export const EmbeddedMetricsExample: React.FC = () => {
  return (
    <div style={{ padding: '20px' }}>
      <h2 style={{ marginBottom: '16px', color: '#333' }}>
        System Performance
      </h2>
      
      <InfrastructureMetricsPanel
        autoRefresh={true}
        refreshInterval={60000} // 1 minute
        showFeedback={false} // Hide feedback for embedded use
        className="embedded-metrics"
      />
      
      <div style={{ marginTop: '20px', fontSize: '14px', color: '#666' }}>
        <p>
          This metrics panel is embedded within a larger dashboard.
          It automatically refreshes every minute to provide up-to-date
          infrastructure performance information.
        </p>
      </div>
    </div>
  );
};

// Example 4: Custom Configuration
export const CustomConfigExample: React.FC = () => {
  return (
    <ServiceHealthOverview
      serviceName="Production API Service"
      autoRefresh={true}
      refreshInterval={10000} // 10 seconds for production monitoring
      className="production-health-overview"
    />
  );
};

/**
 * Integration Notes:
 * 
 * 1. Environment Variables:
 *    Set REACT_APP_METRICS_API_URL to point to your metrics API endpoint
 *    Example: REACT_APP_METRICS_API_URL=https://api.yourservice.com/metrics
 * 
 * 2. API Endpoints Expected:
 *    - GET /api/metrics/current - Current infrastructure metrics
 *    - GET /api/metrics/overview - Comprehensive metrics with history and alerts
 *    - GET /api/metrics/history - Historical metrics data
 *    - GET /api/metrics/alerts - Active alerts
 *    - POST /api/metrics/feedback - Submit user feedback
 *    - GET /api/metrics/config - Metrics configuration
 *    - GET /api/metrics/health - Health check endpoint
 * 
 * 3. Styling:
 *    The components include comprehensive built-in styling, but you can
 *    override styles by providing custom CSS classes or by modifying
 *    the styles in InfrastructureMetrics.styles.ts
 * 
 * 4. Error Handling:
 *    All components include proper error handling and will gracefully
 *    degrade if the metrics API is unavailable
 * 
 * 5. Performance:
 *    Auto-refresh can be disabled or configured with different intervals
 *    based on your monitoring needs and API capacity
 */

export default {
  FullServiceHealthExample,
  StandaloneMetricsExample,
  EmbeddedMetricsExample,
  CustomConfigExample
};