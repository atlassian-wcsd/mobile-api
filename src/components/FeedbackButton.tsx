import React, { useState } from 'react';
import FeedbackForm from './FeedbackForm';

interface FeedbackButtonProps {
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  userEmail?: string;
  onFeedbackSubmitted?: (feedbackId: string) => void;
  className?: string;
}

export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  position = 'bottom-right',
  userEmail,
  onFeedbackSubmitted,
  className = ''
}) => {
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [showSuccessMessage, setShowSuccessMessage] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const getPositionStyles = () => {
    const baseStyles = {
      position: 'fixed' as const,
      zIndex: 1000,
    };

    switch (position) {
      case 'bottom-right':
        return { ...baseStyles, bottom: '20px', right: '20px' };
      case 'bottom-left':
        return { ...baseStyles, bottom: '20px', left: '20px' };
      case 'top-right':
        return { ...baseStyles, top: '20px', right: '20px' };
      case 'top-left':
        return { ...baseStyles, top: '20px', left: '20px' };
      default:
        return { ...baseStyles, bottom: '20px', right: '20px' };
    }
  };

  const handleSuccess = (feedbackId: string) => {
    setIsFormOpen(false);
    setShowSuccessMessage(true);
    setErrorMessage(null);
    onFeedbackSubmitted?.(feedbackId);

    // Hide success message after 3 seconds
    setTimeout(() => {
      setShowSuccessMessage(false);
    }, 3000);
  };

  const handleError = (error: string) => {
    setErrorMessage(error);
    // Hide error message after 5 seconds
    setTimeout(() => {
      setErrorMessage(null);
    }, 5000);
  };

  const handleClose = () => {
    setIsFormOpen(false);
    setErrorMessage(null);
  };

  return (
    <>
      {/* Floating Feedback Button */}
      <div style={getPositionStyles()}>
        <button
          onClick={() => setIsFormOpen(true)}
          className={`feedback-button ${className}`}
          style={{
            backgroundColor: '#007bff',
            color: '#fff',
            border: 'none',
            borderRadius: '50px',
            padding: '12px 20px',
            fontSize: '14px',
            fontWeight: '500',
            cursor: 'pointer',
            boxShadow: '0 4px 12px rgba(0, 123, 255, 0.3)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.3s ease',
            transform: isFormOpen ? 'scale(0.95)' : 'scale(1)',
            opacity: isFormOpen ? 0.8 : 1
          }}
          onMouseEnter={(e) => {
            if (!isFormOpen) {
              e.currentTarget.style.backgroundColor = '#0056b3';
              e.currentTarget.style.transform = 'scale(1.05)';
            }
          }}
          onMouseLeave={(e) => {
            if (!isFormOpen) {
              e.currentTarget.style.backgroundColor = '#007bff';
              e.currentTarget.style.transform = 'scale(1)';
            }
          }}
        >
          <FeedbackIcon />
          Feedback
        </button>
      </div>

      {/* Success Message */}
      {showSuccessMessage && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          backgroundColor: '#d4edda',
          color: '#155724',
          border: '1px solid #c3e6cb',
          borderRadius: '4px',
          padding: '12px 16px',
          zIndex: 1001,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span style={{ fontSize: '16px' }}>✓</span>
          Thank you for your feedback!
        </div>
      )}

      {/* Error Message */}
      {errorMessage && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          backgroundColor: '#f8d7da',
          color: '#721c24',
          border: '1px solid #f5c6cb',
          borderRadius: '4px',
          padding: '12px 16px',
          zIndex: 1001,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          maxWidth: '300px'
        }}>
          <span style={{ fontSize: '16px' }}>⚠</span>
          <div>
            <div style={{ fontWeight: '500' }}>Error</div>
            <div style={{ fontSize: '14px' }}>{errorMessage}</div>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            style={{
              background: 'none',
              border: 'none',
              color: '#721c24',
              cursor: 'pointer',
              fontSize: '18px',
              marginLeft: 'auto'
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Feedback Form Modal */}
      {isFormOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          zIndex: 1000,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '20px'
        }}>
          <div style={{
            maxHeight: '90vh',
            overflowY: 'auto',
            width: '100%',
            maxWidth: '600px'
          }}>
            <FeedbackForm
              onSuccess={handleSuccess}
              onError={handleError}
              onClose={handleClose}
              userEmail={userEmail}
            />
          </div>
        </div>
      )}
    </>
  );
};

const FeedbackIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4l4 4 4-4h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/>
  </svg>
);

export default FeedbackButton;