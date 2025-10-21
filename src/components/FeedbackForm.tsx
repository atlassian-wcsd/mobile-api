import React, { useState, useEffect } from 'react';
import { 
  FeedbackCategory, 
  FeedbackSubmissionRequest,
  FeedbackUtils 
} from '../models/Feedback';
import { FeedbackService } from '../services/FeedbackService';

interface FeedbackFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (feedbackId: string) => void;
  onError?: (error: string) => void;
  userId?: string;
  className?: string;
  initialCategory?: FeedbackCategory;
}

interface FormData {
  rating: number;
  feedbackText: string;
  category: FeedbackCategory;
  contactEmail: string;
}

interface FormErrors {
  rating?: string;
  feedbackText?: string;
  contactEmail?: string;
  general?: string;
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  isOpen,
  onClose,
  onSuccess,
  onError,
  userId,
  className = '',
  initialCategory = FeedbackCategory.GENERAL_FEEDBACK
}) => {
  const [formData, setFormData] = useState<FormData>({
    rating: 0,
    feedbackText: '',
    category: initialCategory,
    contactEmail: ''
  });

  const [errors, setErrors] = useState<FormErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [feedbackService] = useState(() => new FeedbackService());

  // Reset form when opened
  useEffect(() => {
    if (isOpen) {
      setFormData({
        rating: 0,
        feedbackText: '',
        category: initialCategory,
        contactEmail: ''
      });
      setErrors({});
      setIsSubmitted(false);
    }
  }, [isOpen, initialCategory]);

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};

    const ratingError = FeedbackUtils.validateRating(formData.rating);
    if (ratingError) newErrors.rating = ratingError;

    const textError = FeedbackUtils.validateFeedbackText(formData.feedbackText);
    if (textError) newErrors.feedbackText = textError;

    if (formData.contactEmail) {
      const emailError = FeedbackUtils.validateEmail(formData.contactEmail);
      if (emailError) newErrors.contactEmail = emailError;
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
    setErrors({});

    try {
      const request: FeedbackSubmissionRequest = {
        rating: formData.rating,
        feedbackText: formData.feedbackText,
        category: formData.category,
        contactEmail: formData.contactEmail || undefined,
        deviceInfo: FeedbackUtils.getDeviceInfo(),
        metadata: {
          ...FeedbackUtils.getMetadata(),
          userId: userId
        }
      };

      const response = await feedbackService.submitFeedback(request);

      if (response.success && response.feedbackId) {
        setIsSubmitted(true);
        onSuccess?.(response.feedbackId);
        
        // Auto-close after 3 seconds
        setTimeout(() => {
          onClose();
        }, 3000);
      } else {
        setErrors({ general: response.error || 'Failed to submit feedback' });
        onError?.(response.error || 'Failed to submit feedback');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An unexpected error occurred';
      setErrors({ general: errorMessage });
      onError?.(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRatingClick = (rating: number) => {
    setFormData(prev => ({ ...prev, rating }));
    if (errors.rating) {
      setErrors(prev => ({ ...prev, rating: undefined }));
    }
  };

  const handleInputChange = (field: keyof FormData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }));
    }
  };

  if (!isOpen) return null;

  return (
    <div className={`feedback-form-overlay ${className}`} style={overlayStyles}>
      <div className="feedback-form-container" style={containerStyles}>
        <div className="feedback-form-header" style={headerStyles}>
          <h2 style={titleStyles}>
            {isSubmitted ? 'Thank You!' : 'Share Your Feedback'}
          </h2>
          <button 
            onClick={onClose}
            style={closeButtonStyles}
            aria-label="Close feedback form"
          >
            ×
          </button>
        </div>

        {isSubmitted ? (
          <div style={successStyles}>
            <div style={successIconStyles}>✓</div>
            <p>Your feedback has been submitted successfully!</p>
            <p style={successSubtextStyles}>
              We appreciate your input and will review it carefully.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={formStyles}>
            {/* Rating Section */}
            <div style={fieldStyles}>
              <label style={labelStyles}>
                How would you rate your experience? *
              </label>
              <div style={ratingContainerStyles}>
                {[1, 2, 3, 4, 5].map((star) => (
                  <button
                    key={star}
                    type="button"
                    onClick={() => handleRatingClick(star)}
                    style={{
                      ...starButtonStyles,
                      color: star <= formData.rating ? '#ffd700' : '#ddd'
                    }}
                    aria-label={`${star} star${star > 1 ? 's' : ''}`}
                  >
                    ★
                  </button>
                ))}
              </div>
              {errors.rating && (
                <span style={errorStyles}>{errors.rating}</span>
              )}
            </div>

            {/* Category Section */}
            <div style={fieldStyles}>
              <label htmlFor="category" style={labelStyles}>
                Category *
              </label>
              <select
                id="category"
                value={formData.category}
                onChange={(e) => handleInputChange('category', e.target.value)}
                style={selectStyles}
                required
              >
                {Object.values(FeedbackCategory).map((category) => (
                  <option key={category} value={category}>
                    {FeedbackUtils.getCategoryDisplayName(category)}
                  </option>
                ))}
              </select>
            </div>

            {/* Feedback Text Section */}
            <div style={fieldStyles}>
              <label htmlFor="feedbackText" style={labelStyles}>
                Your Feedback *
              </label>
              <textarea
                id="feedbackText"
                value={formData.feedbackText}
                onChange={(e) => handleInputChange('feedbackText', e.target.value)}
                placeholder="Please share your thoughts, suggestions, or report any issues..."
                style={textareaStyles}
                rows={4}
                maxLength={2000}
                required
              />
              <div style={characterCountStyles}>
                {formData.feedbackText.length}/2000 characters
              </div>
              {errors.feedbackText && (
                <span style={errorStyles}>{errors.feedbackText}</span>
              )}
            </div>

            {/* Contact Email Section */}
            <div style={fieldStyles}>
              <label htmlFor="contactEmail" style={labelStyles}>
                Contact Email (Optional)
              </label>
              <input
                id="contactEmail"
                type="email"
                value={formData.contactEmail}
                onChange={(e) => handleInputChange('contactEmail', e.target.value)}
                placeholder="your.email@example.com"
                style={inputStyles}
              />
              <div style={helpTextStyles}>
                Provide your email if you'd like us to follow up on your feedback
              </div>
              {errors.contactEmail && (
                <span style={errorStyles}>{errors.contactEmail}</span>
              )}
            </div>

            {/* General Error */}
            {errors.general && (
              <div style={generalErrorStyles}>
                {errors.general}
              </div>
            )}

            {/* Submit Button */}
            <div style={buttonContainerStyles}>
              <button
                type="button"
                onClick={onClose}
                style={cancelButtonStyles}
                disabled={isSubmitting}
              >
                Cancel
              </button>
              <button
                type="submit"
                style={{
                  ...submitButtonStyles,
                  opacity: isSubmitting ? 0.6 : 1,
                  cursor: isSubmitting ? 'not-allowed' : 'pointer'
                }}
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <>
                    <span style={spinnerStyles}></span>
                    Submitting...
                  </>
                ) : (
                  'Submit Feedback'
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

// Styles
const overlayStyles: React.CSSProperties = {
  position: 'fixed',
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
};

const containerStyles: React.CSSProperties = {
  backgroundColor: 'white',
  borderRadius: '12px',
  boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2)',
  maxWidth: '500px',
  width: '100%',
  maxHeight: '90vh',
  overflow: 'auto'
};

const headerStyles: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '20px 24px 0',
  borderBottom: '1px solid #eee',
  paddingBottom: '16px'
};

const titleStyles: React.CSSProperties = {
  margin: 0,
  fontSize: '24px',
  fontWeight: '600',
  color: '#333'
};

const closeButtonStyles: React.CSSProperties = {
  background: 'none',
  border: 'none',
  fontSize: '24px',
  cursor: 'pointer',
  color: '#666',
  padding: '4px',
  borderRadius: '4px',
  lineHeight: 1
};

const formStyles: React.CSSProperties = {
  padding: '24px'
};

const fieldStyles: React.CSSProperties = {
  marginBottom: '20px'
};

const labelStyles: React.CSSProperties = {
  display: 'block',
  marginBottom: '8px',
  fontWeight: '500',
  color: '#333',
  fontSize: '14px'
};

const ratingContainerStyles: React.CSSProperties = {
  display: 'flex',
  gap: '4px',
  marginBottom: '8px'
};

const starButtonStyles: React.CSSProperties = {
  background: 'none',
  border: 'none',
  fontSize: '24px',
  cursor: 'pointer',
  padding: '4px',
  transition: 'color 0.2s ease'
};

const selectStyles: React.CSSProperties = {
  width: '100%',
  padding: '12px',
  border: '1px solid #ddd',
  borderRadius: '6px',
  fontSize: '14px',
  backgroundColor: 'white'
};

const inputStyles: React.CSSProperties = {
  width: '100%',
  padding: '12px',
  border: '1px solid #ddd',
  borderRadius: '6px',
  fontSize: '14px',
  boxSizing: 'border-box'
};

const textareaStyles: React.CSSProperties = {
  ...inputStyles,
  resize: 'vertical',
  minHeight: '100px',
  fontFamily: 'inherit'
};

const characterCountStyles: React.CSSProperties = {
  fontSize: '12px',
  color: '#666',
  textAlign: 'right',
  marginTop: '4px'
};

const helpTextStyles: React.CSSProperties = {
  fontSize: '12px',
  color: '#666',
  marginTop: '4px'
};

const errorStyles: React.CSSProperties = {
  display: 'block',
  color: '#e74c3c',
  fontSize: '12px',
  marginTop: '4px'
};

const generalErrorStyles: React.CSSProperties = {
  backgroundColor: '#ffeaea',
  color: '#e74c3c',
  padding: '12px',
  borderRadius: '6px',
  marginBottom: '16px',
  fontSize: '14px'
};

const buttonContainerStyles: React.CSSProperties = {
  display: 'flex',
  gap: '12px',
  justifyContent: 'flex-end',
  marginTop: '24px'
};

const cancelButtonStyles: React.CSSProperties = {
  padding: '12px 24px',
  border: '1px solid #ddd',
  borderRadius: '6px',
  backgroundColor: 'white',
  color: '#666',
  cursor: 'pointer',
  fontSize: '14px',
  fontWeight: '500'
};

const submitButtonStyles: React.CSSProperties = {
  padding: '12px 24px',
  border: 'none',
  borderRadius: '6px',
  backgroundColor: '#007bff',
  color: 'white',
  cursor: 'pointer',
  fontSize: '14px',
  fontWeight: '500',
  display: 'flex',
  alignItems: 'center',
  gap: '8px'
};

const spinnerStyles: React.CSSProperties = {
  width: '16px',
  height: '16px',
  border: '2px solid #ffffff40',
  borderTop: '2px solid #ffffff',
  borderRadius: '50%',
  animation: 'spin 1s linear infinite'
};

const successStyles: React.CSSProperties = {
  padding: '40px 24px',
  textAlign: 'center'
};

const successIconStyles: React.CSSProperties = {
  fontSize: '48px',
  color: '#28a745',
  marginBottom: '16px'
};

const successSubtextStyles: React.CSSProperties = {
  color: '#666',
  fontSize: '14px',
  marginTop: '8px'
};

export default FeedbackForm;