import React, { useState } from 'react';
import { FeedbackForm } from './FeedbackForm';
import './FeedbackButton.css';

interface FeedbackButtonProps {
  userId: string;
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  onFeedbackSubmitted?: (feedbackId: string) => void;
  ariaLabel?: string;
}

/**
 * Floating button component that opens the feedback form when clicked
 */
export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  userId,
  position = 'bottom-right',
  onFeedbackSubmitted,
  ariaLabel = 'Send feedback',
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleOpen = () => {
    setIsOpen(true);
  };

  const handleClose = () => {
    setIsOpen(false);
  };

  const handleSubmitSuccess = (feedbackId: string) => {
    if (onFeedbackSubmitted) {
      onFeedbackSubmitted(feedbackId);
    }
    // Form will auto-close after showing success message
  };

  return (
    <>
      {/* Floating Button */}
      <button
        className={`feedback-button feedback-button--${position}`}
        onClick={handleOpen}
        aria-label={ariaLabel}
        title="Send feedback"
      >
        <svg
          width="24"
          height="24"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      </button>

      {/* Modal Overlay and Form */}
      {isOpen && (
        <div className="feedback-modal-overlay" onClick={handleClose}>
          <div
            className="feedback-modal-content"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="feedback-form-title"
          >
            <FeedbackForm
              userId={userId}
              onSubmitSuccess={handleSubmitSuccess}
              onClose={handleClose}
            />
          </div>
        </div>
      )}
    </>
  );
};
