import React, { useState } from 'react';
import { FeedbackForm } from './FeedbackForm';
import { FeedbackCategory } from '../models/Feedback';

interface FeedbackButtonProps {
  userId?: string;
  className?: string;
  style?: React.CSSProperties;
  variant?: 'floating' | 'inline' | 'menu';
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  initialCategory?: FeedbackCategory;
  onFeedbackSubmitted?: (feedbackId: string) => void;
  onFeedbackError?: (error: string) => void;
}

export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  userId,
  className = '',
  style,
  variant = 'floating',
  position = 'bottom-right',
  initialCategory,
  onFeedbackSubmitted,
  onFeedbackError
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

  const getButtonStyles = (): React.CSSProperties => {
    const baseStyles: React.CSSProperties = {
      border: 'none',
      borderRadius: '6px',
      cursor: 'pointer',
      fontSize: '14px',
      fontWeight: '500',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      transition: 'all 0.2s ease',
      ...style
    };

    switch (variant) {
      case 'floating':
        return {
          ...baseStyles,
          position: 'fixed',
          backgroundColor: '#007bff',
          color: 'white',
          padding: '12px 16px',
          boxShadow: '0 4px 12px rgba(0, 123, 255, 0.3)',
          zIndex: 999,
          ...getPositionStyles(position),
          ...style
        };
      
      case 'inline':
        return {
          ...baseStyles,
          backgroundColor: '#007bff',
          color: 'white',
          padding: '10px 16px',
          ...style
        };
      
      case 'menu':
        return {
          ...baseStyles,
          backgroundColor: 'transparent',
          color: '#333',
          padding: '8px 12px',
          border: '1px solid #ddd',
          ...style
        };
      
      default:
        return baseStyles;
    }
  };

  const getPositionStyles = (pos: string): React.CSSProperties => {
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

  const getButtonText = (): string => {
    switch (variant) {
      case 'floating':
        return 'Feedback';
      case 'inline':
        return 'Give Feedback';
      case 'menu':
        return 'Send Feedback';
      default:
        return 'Feedback';
    }
  };

  return (
    <>
      <button
        onClick={handleOpenForm}
        className={`feedback-button ${className}`}
        style={getButtonStyles()}
        aria-label="Open feedback form"
      >
        <FeedbackIcon />
        {getButtonText()}
      </button>

      <FeedbackForm
        isOpen={isFormOpen}
        onClose={handleCloseForm}
        onSuccess={handleFeedbackSuccess}
        onError={handleFeedbackError}
        userId={userId}
        initialCategory={initialCategory}
      />
    </>
  );
};

const FeedbackIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h4l4 4 4-4h4c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/>
  </svg>
);

// Floating Feedback Button Component for easy integration
export const FloatingFeedbackButton: React.FC<Omit<FeedbackButtonProps, 'variant'>> = (props) => (
  <FeedbackButton {...props} variant="floating" />
);

// Inline Feedback Button Component for forms/pages
export const InlineFeedbackButton: React.FC<Omit<FeedbackButtonProps, 'variant'>> = (props) => (
  <FeedbackButton {...props} variant="inline" />
);

// Menu Feedback Button Component for navigation menus
export const MenuFeedbackButton: React.FC<Omit<FeedbackButtonProps, 'variant'>> = (props) => (
  <FeedbackButton {...props} variant="menu" />
);

export default FeedbackButton;