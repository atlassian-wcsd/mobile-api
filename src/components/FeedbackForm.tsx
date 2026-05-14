import React, { useState } from 'react';
import { Feedback, FeedbackCategory, FeedbackStatus } from '../models/Feedback';
import { FeedbackService } from '../services/FeedbackService';

interface FeedbackFormProps {
  userId: string;
  onSubmitSuccess?: (feedback: Feedback) => void;
  onSubmitError?: (error: Error) => void;
  onClose?: () => void;
  className?: string;
}

const CATEGORY_LABELS: Record<FeedbackCategory, string> = {
  [FeedbackCategory.BUG]: 'Bug Report',
  [FeedbackCategory.FEATURE_REQUEST]: 'Feature Request',
  [FeedbackCategory.IMPROVEMENT]: 'Improvement',
  [FeedbackCategory.GENERAL]: 'General Feedback',
};

const MAX_MESSAGE_LENGTH = 2000;

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  userId,
  onSubmitSuccess,
  onSubmitError,
  onClose,
  className,
}) => {
  const [category, setCategory] = useState<FeedbackCategory>(FeedbackCategory.GENERAL);
  const [rating, setRating] = useState<number>(0);
  const [message, setMessage] = useState<string>('');
  const [contactEmail, setContactEmail] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitStatus, setSubmitStatus] = useState<FeedbackStatus | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const feedbackService = new FeedbackService();

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (rating === 0) {
      newErrors.rating = 'Please select a rating';
    }

    if (!feedbackService.validateMessage(message)) {
      newErrors.message = 'Please enter a message (1-2000 characters)';
    }

    if (contactEmail && !feedbackService.validateEmail(contactEmail)) {
      newErrors.contactEmail = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validate()) return;

    setIsSubmitting(true);
    setSubmitStatus(null);

    try {
      const feedback = await feedbackService.createAndSubmitFeedback(
        category,
        rating,
        message,
        userId,
        contactEmail || undefined
      );

      setSubmitStatus(FeedbackStatus.SUBMITTED);
      setCategory(FeedbackCategory.GENERAL);
      setRating(0);
      setMessage('');
      setContactEmail('');
      setErrors({});
      onSubmitSuccess?.(feedback);
    } catch (error) {
      setSubmitStatus(FeedbackStatus.FAILED);
      onSubmitError?.(error instanceof Error ? error : new Error('Failed to submit feedback'));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRatingClick = (value: number) => {
    setRating(value);
    if (errors.rating) {
      setErrors((prev) => {
        const updated = { ...prev };
        delete updated.rating;
        return updated;
      });
    }
  };

  const handleMessageChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    if (value.length <= MAX_MESSAGE_LENGTH) {
      setMessage(value);
      if (errors.message && feedbackService.validateMessage(value)) {
        setErrors((prev) => {
          const updated = { ...prev };
          delete updated.message;
          return updated;
        });
      }
    }
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setContactEmail(value);
    if (errors.contactEmail && (value === '' || feedbackService.validateEmail(value))) {
      setErrors((prev) => {
        const updated = { ...prev };
        delete updated.contactEmail;
        return updated;
      });
    }
  };

  if (submitStatus === FeedbackStatus.SUBMITTED) {
    return (
      <div className={className}>
        <div style={styles.container}>
          <div style={styles.successMessage}>
            <span style={styles.successIcon} role="img" aria-label="success">
              ✅
            </span>
            <h3 style={styles.successTitle}>Thank you for your feedback!</h3>
            <p style={styles.successText}>
              Your feedback has been submitted successfully. We appreciate your input and will use it
              to improve the app.
            </p>
            <button
              onClick={() => {
                setSubmitStatus(null);
                onClose?.();
              }}
              style={styles.button}
              type="button"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={className}>
      <div style={styles.container}>
        <div style={styles.header}>
          <h2 style={styles.title}>Send Us Feedback</h2>
          {onClose && (
            <button
              onClick={onClose}
              style={styles.closeButton}
              aria-label="Close feedback form"
              type="button"
            >
              ✕
            </button>
          )}
        </div>

        <form onSubmit={handleSubmit} noValidate>
          {/* Category Selection */}
          <div style={styles.fieldGroup}>
            <label htmlFor="feedback-category" style={styles.label}>
              Category
            </label>
            <select
              id="feedback-category"
              value={category}
              onChange={(e) => setCategory(e.target.value as FeedbackCategory)}
              style={styles.select}
              disabled={isSubmitting}
            >
              {Object.entries(CATEGORY_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {/* Star Rating */}
          <div style={styles.fieldGroup}>
            <label style={styles.label}>
              Rating <span style={styles.required}>*</span>
            </label>
            <div style={styles.ratingContainer} role="radiogroup" aria-label="Rating">
              {[1, 2, 3, 4, 5].map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => handleRatingClick(value)}
                  style={{
                    ...styles.starButton,
                    color: value <= rating ? '#f5a623' : '#ccc',
                  }}
                  aria-label={`${value} star${value !== 1 ? 's' : ''}`}
                  aria-pressed={value <= rating}
                  disabled={isSubmitting}
                >
                  ★
                </button>
              ))}
            </div>
            {errors.rating && (
              <span style={styles.errorText} role="alert">
                {errors.rating}
              </span>
            )}
          </div>

          {/* Feedback Message */}
          <div style={styles.fieldGroup}>
            <label htmlFor="feedback-message" style={styles.label}>
              Your Feedback <span style={styles.required}>*</span>
            </label>
            <textarea
              id="feedback-message"
              value={message}
              onChange={handleMessageChange}
              placeholder="Tell us what you think..."
              style={styles.textarea}
              rows={5}
              maxLength={MAX_MESSAGE_LENGTH}
              disabled={isSubmitting}
              aria-describedby="message-char-count"
              aria-invalid={!!errors.message}
            />
            <div style={styles.charCount} id="message-char-count">
              {message.length}/{MAX_MESSAGE_LENGTH}
            </div>
            {errors.message && (
              <span style={styles.errorText} role="alert">
                {errors.message}
              </span>
            )}
          </div>

          {/* Contact Email */}
          <div style={styles.fieldGroup}>
            <label htmlFor="feedback-email" style={styles.label}>
              Contact Email (optional)
            </label>
            <input
              id="feedback-email"
              type="email"
              value={contactEmail}
              onChange={handleEmailChange}
              placeholder="your@email.com"
              style={styles.input}
              disabled={isSubmitting}
              aria-invalid={!!errors.contactEmail}
            />
            {errors.contactEmail && (
              <span style={styles.errorText} role="alert">
                {errors.contactEmail}
              </span>
            )}
          </div>

          {/* Error Banner */}
          {submitStatus === FeedbackStatus.FAILED && (
            <div style={styles.errorBanner} role="alert">
              Failed to submit feedback. Please try again.
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            style={{
              ...styles.submitButton,
              opacity: isSubmitting ? 0.7 : 1,
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
            }}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
          </button>
        </form>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '600px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    backgroundColor: '#ffffff',
    borderRadius: '8px',
    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '24px',
  },
  title: {
    margin: 0,
    fontSize: '24px',
    fontWeight: 600,
    color: '#333',
  },
  closeButton: {
    background: 'none',
    border: 'none',
    fontSize: '20px',
    cursor: 'pointer',
    color: '#666',
    padding: '4px 8px',
  },
  fieldGroup: {
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    marginBottom: '6px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#555',
  },
  required: {
    color: '#e74c3c',
  },
  select: {
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    backgroundColor: '#fff',
    boxSizing: 'border-box' as const,
  },
  ratingContainer: {
    display: 'flex',
    gap: '4px',
  },
  starButton: {
    background: 'none',
    border: 'none',
    fontSize: '32px',
    cursor: 'pointer',
    padding: '2px',
    transition: 'transform 0.1s ease',
  },
  textarea: {
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    resize: 'vertical' as const,
    minHeight: '100px',
    boxSizing: 'border-box' as const,
  },
  charCount: {
    textAlign: 'right' as const,
    fontSize: '12px',
    color: '#999',
    marginTop: '4px',
  },
  input: {
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    boxSizing: 'border-box' as const,
  },
  errorText: {
    display: 'block',
    color: '#e74c3c',
    fontSize: '12px',
    marginTop: '4px',
  },
  errorBanner: {
    padding: '12px',
    backgroundColor: '#fdf0ef',
    border: '1px solid #e74c3c',
    borderRadius: '4px',
    color: '#e74c3c',
    fontSize: '14px',
    marginBottom: '16px',
  },
  submitButton: {
    width: '100%',
    padding: '12px 24px',
    fontSize: '16px',
    fontWeight: 600,
    color: '#ffffff',
    backgroundColor: '#007bff',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  button: {
    padding: '10px 24px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#ffffff',
    backgroundColor: '#007bff',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  successMessage: {
    textAlign: 'center' as const,
    padding: '20px',
  },
  successIcon: {
    fontSize: '48px',
    display: 'block',
    marginBottom: '16px',
  },
  successTitle: {
    fontSize: '20px',
    fontWeight: 600,
    color: '#333',
    marginBottom: '8px',
  },
  successText: {
    fontSize: '14px',
    color: '#666',
    marginBottom: '24px',
  },
};

export default FeedbackForm;
