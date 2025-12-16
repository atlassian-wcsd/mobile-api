import React, { useState } from 'react';
import { FeedbackForm } from './FeedbackForm';

interface FeedbackButtonProps {
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  buttonText?: string;
  buttonStyle?: React.CSSProperties;
}

/**
 * Floating feedback button that opens a modal with feedback form
 */
export const FeedbackButton: React.FC<FeedbackButtonProps> = ({
  position = 'bottom-right',
  buttonText = '💬 Feedback',
  buttonStyle,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleOpen = () => {
    setIsOpen(true);
  };

  const handleClose = () => {
    setIsOpen(false);
  };

  const handleSuccess = () => {
    setTimeout(() => {
      setIsOpen(false);
    }, 2000);
  };

  const positionStyles = getPositionStyles(position);

  return (
    <>
      {/* Floating Button */}
      <button
        onClick={handleOpen}
        style={{
          ...styles.floatingButton,
          ...positionStyles,
          ...buttonStyle,
        }}
        aria-label="Open feedback form"
        title="Give us feedback"
      >
        {buttonText}
      </button>

      {/* Modal */}
      {isOpen && (
        <div style={styles.modalOverlay} onClick={handleClose}>
          <div
            style={styles.modalContent}
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="feedback-form-title"
          >
            <button
              onClick={handleClose}
              style={styles.closeButton}
              aria-label="Close feedback form"
            >
              ×
            </button>
            <FeedbackForm onSuccess={handleSuccess} onCancel={handleClose} />
          </div>
        </div>
      )}
    </>
  );
};

function getPositionStyles(
  position: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left'
): React.CSSProperties {
  const baseStyles: React.CSSProperties = {
    position: 'fixed',
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
}

const styles: Record<string, React.CSSProperties> = {
  floatingButton: {
    padding: '12px 20px',
    backgroundColor: '#007bff',
    color: '#fff',
    border: 'none',
    borderRadius: '50px',
    fontSize: '14px',
    fontWeight: '600',
    cursor: 'pointer',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
    transition: 'all 0.3s ease',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  modalOverlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1001,
    padding: '20px',
  },
  modalContent: {
    position: 'relative',
    backgroundColor: '#fff',
    borderRadius: '8px',
    maxWidth: '700px',
    width: '100%',
    maxHeight: '90vh',
    overflow: 'auto',
    boxShadow: '0 10px 40px rgba(0, 0, 0, 0.2)',
  },
  closeButton: {
    position: 'absolute',
    top: '15px',
    right: '15px',
    background: 'none',
    border: 'none',
    fontSize: '32px',
    color: '#999',
    cursor: 'pointer',
    lineHeight: '1',
    padding: '0',
    width: '32px',
    height: '32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '50%',
    transition: 'background-color 0.2s',
  },
};

export default FeedbackButton;
