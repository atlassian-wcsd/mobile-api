import React, { useState, useEffect } from 'react';
import { feedbackService } from '../services/FeedbackService';
import { FeedbackSubmitRequest } from '../models/Feedback';

interface FeedbackFormProps {
  onSuccess?: () => void;
  onCancel?: () => void;
  defaultCategory?: string;
  defaultType?: 'bug' | 'feature' | 'improvement' | 'general';
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  onSuccess,
  onCancel,
  defaultCategory = 'general',
  defaultType = 'general',
}) => {
  const [formData, setFormData] = useState<FeedbackSubmitRequest>({
    feedbackType: defaultType,
    title: '',
    message: '',
    category: defaultCategory,
    rating: undefined,
    email: '',
    allowContact: false,
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<{
    type: 'success' | 'error' | null;
    message: string;
  }>({ type: null, message: '' });

  const [errors, setErrors] = useState<Record<string, string>>({});

  // Track form view
  useEffect(() => {
    feedbackService.trackEvent('feedback', 'feedback_form_viewed', {
      category: defaultCategory,
      type: defaultType,
    });
  }, [defaultCategory, defaultType]);

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.title || formData.title.length < 3) {
      newErrors.title = 'Title must be at least 3 characters';
    }

    if (formData.title.length > 200) {
      newErrors.title = 'Title must be less than 200 characters';
    }

    if (!formData.message || formData.message.length < 10) {
      newErrors.message = 'Message must be at least 10 characters';
    }

    if (formData.message.length > 5000) {
      newErrors.message = 'Message must be less than 5000 characters';
    }

    if (formData.rating && (formData.rating < 1 || formData.rating > 5)) {
      newErrors.rating = 'Rating must be between 1 and 5';
    }

    if (formData.email && !isValidEmail(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);
    setSubmitStatus({ type: null, message: '' });

    try {
      const response = await feedbackService.submitFeedback(formData);

      if (response.success) {
        setSubmitStatus({
          type: 'success',
          message: response.message,
        });

        // Reset form
        setFormData({
          feedbackType: defaultType,
          title: '',
          message: '',
          category: defaultCategory,
          rating: undefined,
          email: '',
          allowContact: false,
        });

        // Call success callback after short delay
        setTimeout(() => {
          if (onSuccess) {
            onSuccess();
          }
        }, 2000);
      } else {
        setSubmitStatus({
          type: 'error',
          message: response.error || 'Failed to submit feedback',
        });
      }
    } catch (error) {
      setSubmitStatus({
        type: 'error',
        message: 'An unexpected error occurred. Please try again.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleInputChange = (
    field: keyof FeedbackSubmitRequest,
    value: any
  ) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    // Clear error for this field
    if (errors[field]) {
      setErrors((prev) => {
        const newErrors = { ...prev };
        delete newErrors[field];
        return newErrors;
      });
    }
  };

  return (
    <div className="feedback-form-container" style={styles.container}>
      <div className="feedback-form" style={styles.form}>
        <h2 style={styles.title}>Share Your Feedback</h2>
        <p style={styles.description}>
          We value your input! Please let us know what you think.
        </p>

        {submitStatus.type && (
          <div
            className={`alert alert-${submitStatus.type}`}
            style={{
              ...styles.alert,
              ...(submitStatus.type === 'success'
                ? styles.alertSuccess
                : styles.alertError),
            }}
          >
            {submitStatus.message}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Feedback Type */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="feedbackType">
              Type <span style={styles.required}>*</span>
            </label>
            <select
              id="feedbackType"
              value={formData.feedbackType}
              onChange={(e) =>
                handleInputChange(
                  'feedbackType',
                  e.target.value as FeedbackSubmitRequest['feedbackType']
                )
              }
              style={styles.select}
              required
              aria-required="true"
            >
              <option value="general">General Feedback</option>
              <option value="bug">Bug Report</option>
              <option value="feature">Feature Request</option>
              <option value="improvement">Improvement Suggestion</option>
            </select>
          </div>

          {/* Category */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="category">
              Category <span style={styles.required}>*</span>
            </label>
            <select
              id="category"
              value={formData.category}
              onChange={(e) => handleInputChange('category', e.target.value)}
              style={styles.select}
              required
              aria-required="true"
            >
              <option value="general">General</option>
              <option value="signature">Signature Feature</option>
              <option value="login">Login/Authentication</option>
              <option value="performance">Performance</option>
              <option value="ui">User Interface</option>
              <option value="other">Other</option>
            </select>
          </div>

          {/* Rating */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="rating">
              Rating (Optional)
            </label>
            <div style={styles.ratingContainer}>
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  type="button"
                  onClick={() => handleInputChange('rating', star)}
                  style={{
                    ...styles.starButton,
                    color:
                      formData.rating && formData.rating >= star
                        ? '#ffc107'
                        : '#ddd',
                  }}
                  aria-label={`Rate ${star} stars`}
                >
                  ★
                </button>
              ))}
              {formData.rating && (
                <button
                  type="button"
                  onClick={() => handleInputChange('rating', undefined)}
                  style={styles.clearRating}
                  aria-label="Clear rating"
                >
                  Clear
                </button>
              )}
            </div>
            {errors.rating && (
              <div style={styles.error}>{errors.rating}</div>
            )}
          </div>

          {/* Title */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="title">
              Title <span style={styles.required}>*</span>
            </label>
            <input
              id="title"
              type="text"
              value={formData.title}
              onChange={(e) => handleInputChange('title', e.target.value)}
              placeholder="Brief summary of your feedback"
              style={{
                ...styles.input,
                ...(errors.title ? styles.inputError : {}),
              }}
              maxLength={200}
              required
              aria-required="true"
              aria-invalid={!!errors.title}
            />
            <div style={styles.charCount}>
              {formData.title.length}/200
            </div>
            {errors.title && <div style={styles.error}>{errors.title}</div>}
          </div>

          {/* Message */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="message">
              Message <span style={styles.required}>*</span>
            </label>
            <textarea
              id="message"
              value={formData.message}
              onChange={(e) => handleInputChange('message', e.target.value)}
              placeholder="Please provide detailed feedback..."
              style={{
                ...styles.textarea,
                ...(errors.message ? styles.inputError : {}),
              }}
              rows={6}
              maxLength={5000}
              required
              aria-required="true"
              aria-invalid={!!errors.message}
            />
            <div style={styles.charCount}>
              {formData.message.length}/5000
            </div>
            {errors.message && (
              <div style={styles.error}>{errors.message}</div>
            )}
          </div>

          {/* Email (optional) */}
          <div style={styles.formGroup}>
            <label style={styles.label} htmlFor="email">
              Email (Optional)
            </label>
            <input
              id="email"
              type="email"
              value={formData.email}
              onChange={(e) => handleInputChange('email', e.target.value)}
              placeholder="your@email.com"
              style={{
                ...styles.input,
                ...(errors.email ? styles.inputError : {}),
              }}
              aria-invalid={!!errors.email}
            />
            {errors.email && <div style={styles.error}>{errors.email}</div>}
          </div>

          {/* Allow Contact */}
          <div style={styles.checkboxGroup}>
            <label style={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={formData.allowContact}
                onChange={(e) =>
                  handleInputChange('allowContact', e.target.checked)
                }
                style={styles.checkbox}
              />
              <span>You may contact me about this feedback</span>
            </label>
          </div>

          {/* Action Buttons */}
          <div style={styles.buttonGroup}>
            <button
              type="submit"
              disabled={isSubmitting}
              style={{
                ...styles.button,
                ...styles.submitButton,
                ...(isSubmitting ? styles.buttonDisabled : {}),
              }}
              aria-busy={isSubmitting}
            >
              {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
            </button>
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                disabled={isSubmitting}
                style={{
                  ...styles.button,
                  ...styles.cancelButton,
                }}
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};

// Inline styles for self-contained component
const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '600px',
    margin: '0 auto',
    padding: '20px',
  },
  form: {
    backgroundColor: '#fff',
    borderRadius: '8px',
    padding: '30px',
    boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)',
  },
  title: {
    fontSize: '24px',
    fontWeight: 'bold',
    marginBottom: '10px',
    color: '#333',
  },
  description: {
    fontSize: '14px',
    color: '#666',
    marginBottom: '20px',
  },
  formGroup: {
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    fontSize: '14px',
    fontWeight: '600',
    marginBottom: '8px',
    color: '#333',
  },
  required: {
    color: '#dc3545',
  },
  input: {
    width: '100%',
    padding: '10px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    boxSizing: 'border-box',
  },
  inputError: {
    borderColor: '#dc3545',
  },
  select: {
    width: '100%',
    padding: '10px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    backgroundColor: '#fff',
    boxSizing: 'border-box',
  },
  textarea: {
    width: '100%',
    padding: '10px',
    fontSize: '14px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    resize: 'vertical',
    fontFamily: 'inherit',
    boxSizing: 'border-box',
  },
  charCount: {
    fontSize: '12px',
    color: '#999',
    textAlign: 'right',
    marginTop: '4px',
  },
  error: {
    fontSize: '12px',
    color: '#dc3545',
    marginTop: '4px',
  },
  ratingContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
  starButton: {
    background: 'none',
    border: 'none',
    fontSize: '32px',
    cursor: 'pointer',
    padding: '0',
    transition: 'color 0.2s',
  },
  clearRating: {
    fontSize: '12px',
    marginLeft: '10px',
    padding: '4px 8px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    backgroundColor: '#fff',
    cursor: 'pointer',
  },
  checkboxGroup: {
    marginBottom: '20px',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    fontSize: '14px',
    color: '#333',
    cursor: 'pointer',
  },
  checkbox: {
    marginRight: '8px',
    cursor: 'pointer',
  },
  buttonGroup: {
    display: 'flex',
    gap: '10px',
    justifyContent: 'flex-end',
    marginTop: '30px',
  },
  button: {
    padding: '12px 24px',
    fontSize: '14px',
    fontWeight: '600',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  },
  submitButton: {
    backgroundColor: '#007bff',
    color: '#fff',
  },
  cancelButton: {
    backgroundColor: '#6c757d',
    color: '#fff',
  },
  buttonDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  },
  alert: {
    padding: '12px',
    borderRadius: '4px',
    marginBottom: '20px',
    fontSize: '14px',
  },
  alertSuccess: {
    backgroundColor: '#d4edda',
    color: '#155724',
    border: '1px solid #c3e6cb',
  },
  alertError: {
    backgroundColor: '#f8d7da',
    color: '#721c24',
    border: '1px solid #f5c6cb',
  },
};

export default FeedbackForm;
