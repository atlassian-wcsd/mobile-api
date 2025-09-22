import { CSSProperties } from 'react';

export const styles = {
  // Main container styles
  metricsContainer: {
    padding: '24px',
    backgroundColor: '#f8f9fa',
    borderRadius: '8px',
    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
    margin: '16px 0'
  } as CSSProperties,

  metricsHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '24px',
    borderBottom: '1px solid #e9ecef',
    paddingBottom: '16px'
  } as CSSProperties,

  metricsTitle: {
    fontSize: '24px',
    fontWeight: '600',
    color: '#212529',
    margin: 0
  } as CSSProperties,

  lastUpdated: {
    fontSize: '14px',
    color: '#6c757d',
    fontStyle: 'italic'
  } as CSSProperties,

  // Grid layout for metrics cards
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
    gap: '20px',
    marginBottom: '24px'
  } as CSSProperties,

  // Individual metric card styles
  metricCard: {
    backgroundColor: '#ffffff',
    borderRadius: '8px',
    padding: '20px',
    boxShadow: '0 1px 4px rgba(0, 0, 0, 0.1)',
    border: '1px solid #e9ecef',
    transition: 'transform 0.2s ease, box-shadow 0.2s ease'
  } as CSSProperties,

  metricCardHover: {
    transform: 'translateY(-2px)',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
  } as CSSProperties,

  metricCardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '16px'
  } as CSSProperties,

  metricTitle: {
    fontSize: '16px',
    fontWeight: '600',
    color: '#495057',
    margin: 0
  } as CSSProperties,

  metricIcon: {
    width: '24px',
    height: '24px',
    color: '#6c757d'
  } as CSSProperties,

  // Status indicators
  statusIndicator: {
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    display: 'inline-block',
    marginRight: '8px'
  } as CSSProperties,

  statusHealthy: {
    backgroundColor: '#28a745'
  } as CSSProperties,

  statusWarning: {
    backgroundColor: '#ffc107'
  } as CSSProperties,

  statusCritical: {
    backgroundColor: '#dc3545'
  } as CSSProperties,

  statusUnknown: {
    backgroundColor: '#6c757d'
  } as CSSProperties,

  // Metric value display
  metricValue: {
    fontSize: '32px',
    fontWeight: '700',
    color: '#212529',
    lineHeight: '1.2',
    marginBottom: '8px'
  } as CSSProperties,

  metricUnit: {
    fontSize: '14px',
    color: '#6c757d',
    fontWeight: '400'
  } as CSSProperties,

  metricDetails: {
    marginTop: '16px'
  } as CSSProperties,

  metricDetailRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '4px 0',
    fontSize: '14px',
    color: '#495057'
  } as CSSProperties,

  // Progress bars
  progressBar: {
    width: '100%',
    height: '8px',
    backgroundColor: '#e9ecef',
    borderRadius: '4px',
    overflow: 'hidden',
    marginTop: '8px'
  } as CSSProperties,

  progressFill: {
    height: '100%',
    borderRadius: '4px',
    transition: 'width 0.3s ease'
  } as CSSProperties,

  // Alert section
  alertsSection: {
    marginTop: '24px',
    padding: '20px',
    backgroundColor: '#ffffff',
    borderRadius: '8px',
    border: '1px solid #e9ecef'
  } as CSSProperties,

  alertsHeader: {
    fontSize: '18px',
    fontWeight: '600',
    color: '#495057',
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center'
  } as CSSProperties,

  alertItem: {
    padding: '12px 16px',
    borderRadius: '6px',
    marginBottom: '8px',
    border: '1px solid',
    display: 'flex',
    alignItems: 'flex-start',
    gap: '12px'
  } as CSSProperties,

  alertWarning: {
    backgroundColor: '#fff3cd',
    borderColor: '#ffeaa7',
    color: '#856404'
  } as CSSProperties,

  alertCritical: {
    backgroundColor: '#f8d7da',
    borderColor: '#f5c6cb',
    color: '#721c24'
  } as CSSProperties,

  alertIcon: {
    width: '20px',
    height: '20px',
    marginTop: '2px'
  } as CSSProperties,

  alertContent: {
    flex: 1
  } as CSSProperties,

  alertMessage: {
    fontSize: '14px',
    fontWeight: '500',
    marginBottom: '4px'
  } as CSSProperties,

  alertTimestamp: {
    fontSize: '12px',
    opacity: 0.8
  } as CSSProperties,

  // Loading states
  loadingContainer: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    padding: '40px',
    color: '#6c757d'
  } as CSSProperties,

  loadingSpinner: {
    width: '32px',
    height: '32px',
    border: '3px solid #e9ecef',
    borderTop: '3px solid #007bff',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    marginRight: '12px'
  } as CSSProperties,

  // Error states
  errorContainer: {
    padding: '20px',
    backgroundColor: '#f8d7da',
    borderRadius: '8px',
    border: '1px solid #f5c6cb',
    color: '#721c24',
    textAlign: 'center'
  } as CSSProperties,

  errorMessage: {
    fontSize: '16px',
    fontWeight: '500',
    marginBottom: '8px'
  } as CSSProperties,

  errorDetails: {
    fontSize: '14px',
    opacity: 0.8
  } as CSSProperties,

  // Feedback section
  feedbackSection: {
    marginTop: '24px',
    padding: '20px',
    backgroundColor: '#ffffff',
    borderRadius: '8px',
    border: '1px solid #e9ecef'
  } as CSSProperties,

  feedbackHeader: {
    fontSize: '18px',
    fontWeight: '600',
    color: '#495057',
    marginBottom: '16px'
  } as CSSProperties,

  feedbackForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  } as CSSProperties,

  feedbackRow: {
    display: 'flex',
    gap: '16px',
    alignItems: 'center'
  } as CSSProperties,

  feedbackLabel: {
    fontSize: '14px',
    fontWeight: '500',
    color: '#495057',
    minWidth: '80px'
  } as CSSProperties,

  feedbackInput: {
    flex: 1,
    padding: '8px 12px',
    border: '1px solid #ced4da',
    borderRadius: '4px',
    fontSize: '14px'
  } as CSSProperties,

  feedbackTextarea: {
    flex: 1,
    padding: '8px 12px',
    border: '1px solid #ced4da',
    borderRadius: '4px',
    fontSize: '14px',
    minHeight: '80px',
    resize: 'vertical'
  } as CSSProperties,

  feedbackButton: {
    padding: '10px 20px',
    backgroundColor: '#007bff',
    color: '#ffffff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'background-color 0.2s ease'
  } as CSSProperties,

  feedbackButtonHover: {
    backgroundColor: '#0056b3'
  } as CSSProperties,

  // Responsive design
  '@media (max-width: 768px)': {
    metricsGrid: {
      gridTemplateColumns: '1fr'
    },
    metricsHeader: {
      flexDirection: 'column',
      alignItems: 'flex-start',
      gap: '8px'
    },
    feedbackRow: {
      flexDirection: 'column',
      alignItems: 'flex-start'
    },
    feedbackLabel: {
      minWidth: 'auto'
    }
  } as CSSProperties,

  // Utility classes
  textCenter: {
    textAlign: 'center'
  } as CSSProperties,

  textRight: {
    textAlign: 'right'
  } as CSSProperties,

  marginBottom: {
    marginBottom: '16px'
  } as CSSProperties,

  marginTop: {
    marginTop: '16px'
  } as CSSProperties,

  hidden: {
    display: 'none'
  } as CSSProperties,

  visible: {
    display: 'block'
  } as CSSProperties
};

// CSS animations (to be added to global styles)
export const globalStyles = `
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .metrics-fade-in {
    animation: fadeIn 0.3s ease-in;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .metrics-card-hover:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }

  .feedback-button:hover {
    background-color: #0056b3;
  }

  .feedback-button:disabled {
    background-color: #6c757d;
    cursor: not-allowed;
  }
`;

export default styles;