import React, { useState } from 'react';
import FeedbackForm from './FeedbackForm';

interface FeedbackButtonProps {
  /** Button text */
  text?: string;
  /** Button position (for floating button) */
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left' | 'inline';
  /** Custom CSS class */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
  /** Pre-filled user information */
  userInfo?: {
    userId?: string;
    email?: string;
    name?: string;
  };
  /** Callback when feedback is successfully submitted */
  onFeedbackSubmitted?: (feedbackId: string) => void;
  /** Callback when feedback submission fails */
  onFeedbackError?: (error: string) => void;
  /** Whether to show as floating action button */
  floating?: boolean;
  /** Button size */
  size?: 'small' | 'medium' | 'large';
  /** Button variant */
  variant?: 'primary' | 'secondary' | 'outline';
}

export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  text = 'Feedback',
  position = 'bottom-right',
  className = '',
  style,
  userInfo,
  onFeedbackSubmitted,
  onFeedbackError,
  floating = false,
  size = 'medium',
  variant = 'primary'
}) => {
  const [isFormOpen, setIsFormOpen] = useState(false);

  const handleOpenForm = () => {
    setIsFormOpen(true);
  };

  const handleCloseForm = () => {
    setIsFormOpen(false);
  };

  const handleFeedbackSuccess = (feedbackId: string) => {
    onFeedbackSubmitted?.(feedbackId);
    // Form will auto-close after success
  };

  const handleFeedbackError = (error: string) => {
    onFeedbackError?.(error);
  };

  const getButtonStyles = () => {
    const baseStyles = {
      border: 'none',
      borderRadius: floating ? '50%' : '6px',
      cursor: 'pointer',
      fontWeight: '500',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '8px',
      transition: 'all 0.2s ease',
      outline: 'none',
      fontFamily: 'inherit',
      ...style
    };

    // Size styles
    const sizeStyles = {
      small: {
        padding: floating ? '12px' : '8px 16px',
        fontSize: '14px',
        width: floating ? '48px' : 'auto',
        height: floating ? '48px' : 'auto'
      },
      medium: {
        padding: floating ? '16px' : '12px 20px',
        fontSize: '16px',
        width: floating ? '56px' : 'auto',
        height: floating ? '56px' : 'auto'
      },
      large: {
        padding: floating ? '20px' : '16px 24px',
        fontSize: '18px',
        width: floating ? '64px' : 'auto',
        height: floating ? '64px' : 'auto'
      }
    };

    // Variant styles
    const variantStyles = {
      primary: {
        backgroundColor: '#007bff',
        color: '#fff',
        boxShadow: floating ? '0 4px 12px rgba(0, 123, 255, 0.3)' : 'none'
      },
      secondary: {
        backgroundColor: '#6c757d',
        color: '#fff',
        boxShadow: floating ? '0 4px 12px rgba(108, 117, 125, 0.3)' : 'none'
      },
      outline: {
        backgroundColor: 'transparent',
        color: '#007bff',
        border: '2px solid #007bff',
        boxShadow: floating ? '0 4px 12px rgba(0, 123, 255, 0.2)' : 'none'
      }
    };

    // Position styles for floating button
    const positionStyles = floating ? {
      position: 'fixed' as const,
      zIndex: 999,
      ...getPositionCoordinates(position)
    } : {};

    return {
      ...baseStyles,
      ...sizeStyles[size],
      ...variantStyles[variant],
      ...positionStyles
    };
  };

  const getPositionCoordinates = (pos: string) => {
    const offset = '20px';
    switch (pos) {
      case 'bottom-right':
        return { bottom: offset, right: offset };
      case 'bottom-left':
        return { bottom: offset, left: offset };
      case 'top-right':
        return { top: offset, right: offset };
      case 'top-left':
        return { top: offset, left: offset };
      default:
        return { bottom: offset, right: offset };
    }
  };

  const getButtonContent = () => {
    if (floating) {
      return (
        <FeedbackIcon />
      );
    }
    
    return (
      <>
        <FeedbackIcon />
        {text}
      </>
    );
  };

  return (
    <>
      <button
        onClick={handleOpenForm}
        className={`feedback-button ${className}`}
        style={getButtonStyles()}
        aria-label={floating ? 'Open feedback form' : text}
        title={floating ? 'Send feedback' : undefined}
      >
        {getButtonContent()}
      </button>

      <FeedbackForm
        isOpen={isFormOpen}
        onClose={handleCloseForm}
        onSuccess={handleFeedbackSuccess}
        onError={handleFeedbackError}
        userInfo={userInfo}
      />

      {/* Add CSS animation for spinner */}
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .feedback-button:hover {
          transform: ${floating ? 'scale(1.05)' : 'translateY(-1px)'};
          box-shadow: ${floating ? '0 6px 16px rgba(0, 123, 255, 0.4)' : '0 2px 8px rgba(0, 0, 0, 0.1)'};
        }
        
        .feedback-button:active {
          transform: ${floating ? 'scale(0.95)' : 'translateY(0)'};
        }
      `}</style>
    </>
  );
};

// Feedback icon component
const FeedbackIcon: React.FC = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4l4 4 4-4h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/>
  </svg>
);

export default FeedbackButton;