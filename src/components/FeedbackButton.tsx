import React, { useState } from 'react';
import FeedbackForm from './FeedbackForm';

interface FeedbackButtonProps {
  authToken?: string;
  userEmail?: string;
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  className?: string;
  onFeedbackSubmitted?: (feedbackId: string) => void;
  onError?: (error: string) => void;
}

export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  authToken,
  userEmail,
  position = 'bottom-right',
  className = '',
  onFeedbackSubmitted,
  onError
}) => {
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [isHovered, setIsHovered] = useState(false);

  const getPositionStyles = () => {
    const baseStyles = {
      position: 'fixed' as const,
      zIndex: 999,
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
    onFeedbackSubmitted?.(feedbackId);
  };

  const handleError = (error: string) => {
    onError?.(error);
  };

  return (
    <>
      <button
        onClick={() => setIsFormOpen(true)}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className={`feedback-button ${className}`}
        style={{
          ...getPositionStyles(),
          backgroundColor: isHovered ? '#0056b3' : '#007bff',
          color: 'white',
          border: 'none',
          borderRadius: '50px',
          padding: '12px 20px',
          fontSize: '14px',
          fontWeight: '500',
          cursor: 'pointer',
          boxShadow: '0 4px 12px rgba(0, 123, 255, 0.3)',
          transition: 'all 0.3s ease',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          transform: isHovered ? 'translateY(-2px)' : 'translateY(0)',
        }}
        title="Send feedback about this app"
      >
        <FeedbackIcon />
        <span>Feedback</span>
      </button>

      <FeedbackForm
        isOpen={isFormOpen}
        onClose={() => setIsFormOpen(false)}
        onSuccess={handleSuccess}
        onError={handleError}
        authToken={authToken}
        userEmail={userEmail}
      />
    </>
  );
};

const FeedbackIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4l4 4 4-4h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/>
  </svg>
);

export default FeedbackButton;