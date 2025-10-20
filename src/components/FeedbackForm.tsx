import React, { useState, useEffect } from 'react';
import { FeedbackService, FeedbackUtils } from '../services/FeedbackService';
import { FeedbackType, FeedbackSubmissionRequest } from '../models/Feedback';

interface FeedbackFormProps {
  /** Whether the form is visible */
  isOpen: boolean;
  /** Callback when form is closed */
  onClose: () => void;
  /** Callback when feedback is successfully submitted */
  onSuccess?: (feedbackId: string) => void;
  /** Callback when feedback submission fails */
  onError?: (error: string) => void;
  /** Pre-filled user information */
  userInfo?: {
    userId?: string;
    email?: string;
    name?: string;
  };
  /** Custom CSS class */
  className?: string;
  /** Whether to show as modal or inline */
  modal?: boolean;
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  isOpen,
  onClose,
  onSuccess,
  onError,
  userInfo,
  className = '',
  modal = true
}) => {
  const [formData, setFormData] = useState<FeedbackSubmissionRequest>({
    email: userInfo?.email || '',
    name: userInfo?.name || '',
    type: FeedbackType.GENERAL_FEEDBACK,
    rating: 5,
    subject: '',
    message: '',
    page: window.location.pathname
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'success' | 'error'>('idle');

  const feedbackService = new FeedbackService();

  // Reset form when opened
  useEffect(() => {
    if (isOpen) {
      setFormData({
        email: userInfo?.email || '',
        name: userInfo?.name || '',
        type: FeedbackType.GENERAL_FEEDBACK,
        rating: 5,
        subject: '',
        message: '',
        page: window.location.pathname
      });
      setErrors({});
      setSubmitStatus('idle');
    }
  }, [isOpen, userInfo]);

  const handleInputChange = (field: keyof FeedbackSubmissionRequest, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.subject.trim()) {
      newErrors.subject = 'Subject is required';
    } else if (formData.subject.length > 200) {
      newErrors.subject = 'Subject must be 200 characters or less';
    }

    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    } else if (formData.message.length > 2000) {
      newErrors.message = 'Message must be 2000 characters or less';
    }

    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (formData.rating < 1 || formData.rating > 5) {
      newErrors.rating = 'Rating must be between 1 and 5';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);
    setSubmitStatus('idle');

    try {
      const response = await feedbackService.submitFeedback(formData);
      
      if (response.success && response.feedbackId) {
        setSubmitStatus('success');
        onSuccess?.(response.feedbackId);
        
        // Auto-close after success
        setTimeout(() => {
          onClose();
        }, 2000);
      } else {
        setSubmitStatus('error');
        onError?.(response.error || 'Failed to submit feedback');
      }
    } catch (error) {
      setSubmitStatus('error');
      const errorMessage = error instanceof Error ? error.message : 'Failed to submit feedback';
      onError?.(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      onClose();
    }
  };

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      handleClose();
    }
  };

  if (!isOpen) {
    return null;
  }

  const formContent = (
    <div className={`feedback-form ${className}`} style={formStyles.container}>
      <div style={formStyles.header}>
        <h2 style={formStyles.title}>Send Feedback</h2>
        <button
          onClick={handleClose}
          disabled={isSubmitting}
          style={formStyles.closeButton}
          aria-label="Close feedback form"
        >
          ×
        </button>
      </div>

      {submitStatus === 'success' && (
        <div style={formStyles.successMessage}>
          ✓ Thank you! Your feedback has been submitted successfully.
        </div>
      )}

      {submitStatus === 'error' && (
        <div style={formStyles.errorMessage}>
          ✗ Failed to submit feedback. Please try again.
        </div>
      )}

      <form onSubmit={handleSubmit} style={formStyles.form}>
        {/* Contact Information */}
        <div style={formStyles.section}>
          <h3 style={formStyles.sectionTitle}>Contact Information (Optional)</h3>
          
          <div style={formStyles.row}>
            <div style={formStyles.field}>
              <label style={formStyles.label}>Name</label>
              <input
                type="text"
                value={formData.name || ''}
                onChange={(e) => handleInputChange('name', e.target.value)}
                style={formStyles.input}
                placeholder="Your name"
                disabled={isSubmitting}
              />
            </div>
            
            <div style={formStyles.field}>
              <label style={formStyles.label}>Email</label>
              <input
                type="email"
                value={formData.email || ''}
                onChange={(e) => handleInputChange('email', e.target.value)}
                style={{
                  ...formStyles.input,
                  ...(errors.email ? formStyles.inputError : {})
                }}
                placeholder="your.email@example.com"
                disabled={isSubmitting}
              />
              {errors.email && <span style={formStyles.errorText}>{errors.email}</span>}
            </div>
          </div>
        </div>

        {/* Feedback Type */}
        <div style={formStyles.field}>
          <label style={formStyles.label}>Feedback Type *</label>
          <select
            value={formData.type}
            onChange={(e) => handleInputChange('type', e.target.value as FeedbackType)}
            style={formStyles.select}
            disabled={isSubmitting}
          >
            {Object.values(FeedbackType).map(type => (
              <option key={type} value={type}>
                {FeedbackUtils.getFeedbackTypeLabel(type)}
              </option>
            ))}
          </select>
        </div>

        {/* Rating */}
        <div style={formStyles.field}>
          <label style={formStyles.label}>Overall Rating *</label>
          <div style={formStyles.ratingContainer}>
            {[1, 2, 3, 4, 5].map(star => (
              <button
                key={star}
                type="button"
                onClick={() => handleInputChange('rating', star)}
                style={{
                  ...formStyles.starButton,
                  color: star <= formData.rating ? '#ffc107' : '#e0e0e0'
                }}
                disabled={isSubmitting}
                aria-label={`Rate ${star} stars`}
              >
                ★
              </button>
            ))}
            <span style={formStyles.ratingText}>
              {formData.rating} of 5 stars
            </span>
          </div>
          {errors.rating && <span style={formStyles.errorText}>{errors.rating}</span>}
        </div>

        {/* Subject */}
        <div style={formStyles.field}>
          <label style={formStyles.label}>Subject *</label>
          <input
            type="text"
            value={formData.subject}
            onChange={(e) => handleInputChange('subject', e.target.value)}
            style={{
              ...formStyles.input,
              ...(errors.subject ? formStyles.inputError : {})
            }}
            placeholder="Brief summary of your feedback"
            maxLength={200}
            disabled={isSubmitting}
            required
          />
          <div style={formStyles.charCount}>
            {formData.subject.length}/200
          </div>
          {errors.subject && <span style={formStyles.errorText}>{errors.subject}</span>}
        </div>

        {/* Message */}
        <div style={formStyles.field}>
          <label style={formStyles.label}>Message *</label>
          <textarea
            value={formData.message}
            onChange={(e) => handleInputChange('message', e.target.value)}
            style={{
              ...formStyles.textarea,
              ...(errors.message ? formStyles.inputError : {})
            }}
            placeholder="Please provide detailed feedback..."
            maxLength={2000}
            rows={6}
            disabled={isSubmitting}
            required
          />
          <div style={formStyles.charCount}>
            {formData.message.length}/2000
          </div>
          {errors.message && <span style={formStyles.errorText}>{errors.message}</span>}
        </div>

        {/* Submit Buttons */}
        <div style={formStyles.buttonContainer}>
          <button
            type="button"
            onClick={handleClose}
            disabled={isSubmitting}
            style={formStyles.cancelButton}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting || submitStatus === 'success'}
            style={{
              ...formStyles.submitButton,
              ...(isSubmitting ? formStyles.submitButtonDisabled : {})
            }}
          >
            {isSubmitting ? (
              <>
                <div style={formStyles.spinner} />
                Submitting...
              </>
            ) : (
              'Submit Feedback'
            )}
          </button>
        </div>
      </form>
    </div>
  );

  if (modal) {
    return (
      <div style={formStyles.overlay} onClick={handleBackdropClick}>
        {formContent}
      </div>
    );
  }

  return formContent;
};

// Styles
const formStyles = {
  overlay: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: '20px'
  },
  container: {
    backgroundColor: '#fff',
    borderRadius: '8px',
    padding: '24px',
    maxWidth: '600px',
    width: '100%',
    maxHeight: '90vh',
    overflowY: 'auto' as const,
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.15)'
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '20px',
    borderBottom: '1px solid #e0e0e0',
    paddingBottom: '16px'
  },
  title: {
    margin: 0,
    fontSize: '24px',
    fontWeight: '600',
    color: '#333'
  },
  closeButton: {
    background: 'none',
    border: 'none',
    fontSize: '24px',
    cursor: 'pointer',
    color: '#666',
    padding: '4px',
    borderRadius: '4px',
    width: '32px',
    height: '32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  successMessage: {
    backgroundColor: '#d4edda',
    color: '#155724',
    padding: '12px',
    borderRadius: '4px',
    marginBottom: '16px',
    border: '1px solid #c3e6cb'
  },
  errorMessage: {
    backgroundColor: '#f8d7da',
    color: '#721c24',
    padding: '12px',
    borderRadius: '4px',
    marginBottom: '16px',
    border: '1px solid #f5c6cb'
  },
  form: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '16px'
  },
  section: {
    marginBottom: '8px'
  },
  sectionTitle: {
    fontSize: '16px',
    fontWeight: '500',
    color: '#555',
    marginBottom: '12px',
    margin: '0 0 12px 0'
  },
  row: {
    display: 'flex',
    gap: '16px',
    flexWrap: 'wrap' as const
  },
  field: {
    display: 'flex',
    flexDirection: 'column' as const,
    flex: 1,
    minWidth: '200px'
  },
  label: {
    fontSize: '14px',
    fontWeight: '500',
    color: '#333',
    marginBottom: '6px'
  },
  input: {
    padding: '10px 12px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '14px',
    transition: 'border-color 0.2s ease',
    outline: 'none'
  },
  inputError: {
    borderColor: '#dc3545'
  },
  select: {
    padding: '10px 12px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '14px',
    backgroundColor: '#fff',
    outline: 'none'
  },
  textarea: {
    padding: '10px 12px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '14px',
    resize: 'vertical' as const,
    fontFamily: 'inherit',
    outline: 'none'
  },
  ratingContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px'
  },
  starButton: {
    background: 'none',
    border: 'none',
    fontSize: '24px',
    cursor: 'pointer',
    padding: '4px',
    transition: 'color 0.2s ease'
  },
  ratingText: {
    marginLeft: '12px',
    fontSize: '14px',
    color: '#666'
  },
  charCount: {
    fontSize: '12px',
    color: '#666',
    textAlign: 'right' as const,
    marginTop: '4px'
  },
  errorText: {
    fontSize: '12px',
    color: '#dc3545',
    marginTop: '4px'
  },
  buttonContainer: {
    display: 'flex',
    gap: '12px',
    justifyContent: 'flex-end',
    marginTop: '8px'
  },
  cancelButton: {
    padding: '10px 20px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    backgroundColor: '#fff',
    color: '#666',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500'
  },
  submitButton: {
    padding: '10px 20px',
    border: 'none',
    borderRadius: '4px',
    backgroundColor: '#007bff',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
    display: 'flex',
    alignItems: 'center',
    gap: '8px'
  },
  submitButtonDisabled: {
    backgroundColor: '#6c757d',
    cursor: 'not-allowed'
  },
  spinner: {
    width: '16px',
    height: '16px',
    border: '2px solid #ffffff40',
    borderTop: '2px solid #ffffff',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite'
  }
};

export default FeedbackForm;