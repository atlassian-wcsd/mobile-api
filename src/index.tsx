import React from 'react';
import ReactDOM from 'react-dom';
import App from './components/App';

// Global CSS reset and base styles
const globalStyles = `
  * {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
      'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
      sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    background-color: #f5f5f5;
  }

  code {
    font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
      monospace;
  }

  /* Feedback system specific styles */
  .feedback-modal-overlay {
    backdrop-filter: blur(2px);
  }

  .feedback-button {
    transition: all 0.3s ease;
  }

  .feedback-button:hover {
    transform: translateY(-2px);
  }

  /* Signature canvas styles */
  .signature-canvas {
    margin: 20px 0;
  }

  .signature-canvas canvas {
    border: 2px solid #ddd;
    border-radius: 8px;
    cursor: crosshair;
    transition: border-color 0.2s ease;
  }

  .signature-canvas canvas:hover {
    border-color: #007bff;
  }

  /* Apple login button styles */
  .apple-login-button {
    transition: all 0.2s ease;
  }

  .apple-login-button:hover {
    opacity: 0.9;
    transform: translateY(-1px);
  }

  /* Responsive design */
  @media (max-width: 768px) {
    .feedback-modal {
      margin: 10px;
      width: calc(100% - 20px);
    }
    
    .signature-canvas canvas {
      width: 100%;
      height: auto;
    }
  }

  /* Animation keyframes */
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .fade-in {
    animation: fadeIn 0.3s ease-out;
  }
`;

// Inject global styles
const styleElement = document.createElement('style');
styleElement.textContent = globalStyles;
document.head.appendChild(styleElement);

// Error boundary component
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error?: Error }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Application error:', error, errorInfo);
    
    // Store error in localStorage for feedback system
    const errorLogs = JSON.parse(localStorage.getItem('app_error_logs') || '[]');
    errorLogs.push({
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      componentStack: errorInfo.componentStack
    });
    
    // Keep only last 10 errors
    if (errorLogs.length > 10) {
      errorLogs.splice(0, errorLogs.length - 10);
    }
    
    localStorage.setItem('app_error_logs', JSON.stringify(errorLogs));
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '40px',
          textAlign: 'center',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
        }}>
          <h1 style={{ color: '#dc3545', marginBottom: '16px' }}>
            Oops! Something went wrong
          </h1>
          <p style={{ color: '#666', marginBottom: '24px' }}>
            We're sorry, but something unexpected happened. Please refresh the page and try again.
          </p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button
              onClick={() => window.location.reload()}
              style={{
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                padding: '12px 24px',
                cursor: 'pointer',
                fontSize: '16px'
              }}
            >
              Refresh Page
            </button>
            <button
              onClick={() => {
                // Reset error state to show feedback form
                this.setState({ hasError: false });
              }}
              style={{
                backgroundColor: '#28a745',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                padding: '12px 24px',
                cursor: 'pointer',
                fontSize: '16px'
              }}
            >
              Report This Issue
            </button>
          </div>
          {this.state.error && (
            <details style={{ marginTop: '24px', textAlign: 'left' }}>
              <summary style={{ cursor: 'pointer', color: '#666' }}>
                Technical Details
              </summary>
              <pre style={{
                backgroundColor: '#f8f9fa',
                border: '1px solid #dee2e6',
                borderRadius: '4px',
                padding: '12px',
                marginTop: '8px',
                fontSize: '12px',
                overflow: 'auto'
              }}>
                {this.state.error.stack}
              </pre>
            </details>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

// Initialize session ID for feedback tracking
if (!sessionStorage.getItem('sessionId')) {
  sessionStorage.setItem('sessionId', 
    Math.random().toString(36).substring(2, 15) + 
    Math.random().toString(36).substring(2, 15)
  );
}

// Render the application
ReactDOM.render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
  document.getElementById('root')
);

// Service worker registration (optional)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        console.log('SW registered: ', registration);
      })
      .catch((registrationError) => {
        console.log('SW registration failed: ', registrationError);
      });
  });
}