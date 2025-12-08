import React, { useState } from 'react';
import { FeedbackService } from '../services/FeedbackService';
import './FeedbackForm.css';

interface FeedbackFormProps {
  userId: string;
  onSubmitSuccess?: (feedbackId: string) => void;
  onSubmitError?: (error: string) => void;
  onClose?: () => void;
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  userId,
  onSubmitSuccess,
  onSubmitError,
  onClose,
}) => {
  const [message, setMessage] = useState('');
  const [rating, setRating] = useState<number>(0);
  const [contactInfo, setContactInfo] = useState('');
  const [category, setCategory] = useState<'bug' | 'feature-request' | 'general' | 'other'>('general');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitMessage, setSubmitMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [errors, setErrors] = useState<string[]>([]);

  const feedbackService = new FeedbackService();

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrors([]);
    setSubmitMessage(null);

    // Validate feedback
    const validation = feedbackService.validateFeedback(message, rating);
    if (!validation.valid) {
      setErrors(validation.errors);
      if (onSubmitError) {
        onSubmitError(validation.errors.join(', '));
      }
      return;
    }

    setIsSubmitting(true);

    try {
      // Submit feedback
      const feedback = feedbackService.submitFeedback(
        userId,
        message,
        rating,
        contactInfo || undefined,
        category
      );

      setSubmitMessage({
        type: 'success',
        text: 'Thank you! Your feedback has been submitted successfully.'
      });

      // Reset form
      setMessage('');
      setRating(0);
      setContactInfo('');
      setCategory('general');

      if (onSubmitSuccess) {
        onSubmitSuccess(feedback.id);
      }

      // Auto-close after success message
      setTimeout(() => {
        if (onClose) {
          onClose();
        }
      }, 2000);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to submit feedback';
      setSubmitMessage({
        type: 'error',
        text: errorMessage
      });

      if (onSubmitError) {
        onSubmitError(errorMessage);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRatingChange = (value: number) => {
    setRating(value);
    // Clear rating error if it exists
    setErrors(errors.filter(err => !err.includes('Rating')));
  };

  const handleMessageChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newMessage = event.target.value;
    setMessage(newMessage);
    // Clear message error if it exists
    setErrors(errors.filter(err => !err.includes('message')));
  };

  const characterCount = message.length;
  const maxCharacters = 5000;
  const characterPercentage = (characterCount / maxCharacters) * 100;

  return (
    <div className="feedback-form-container">
      <div className="feedback-form-header">
        <h2>Send Us Your Feedback</h2>
        {onClose && (
          <button
            className="feedback-form-close-btn"
            onClick={onClose}
            aria-label="Close feedback form"
          >
            ✕
          </button>
        )}
      </div>

      {submitMessage && (
        <div className={`feedback-form-message feedback-form-message--${submitMessage.type}`}>
          {submitMessage.text}
        </div>
      )}

      {errors.length > 0 && (
        <div className="feedback-form-errors">
          <ul>
            {errors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      )}

      <form onSubmit={handleSubmit} className="feedback-form">
        {/* Rating Field */}
        <div className="feedback-form-field">
          <label htmlFor="rating" className="feedback-form-label">
            How would you rate your experience? <span className="required">*</span>
          </label>
          <div className="feedback-form-rating">
            {[1, 2, 3, 4, 5].map((value) => (
              <button
                key={value}
                type="button"
                className={`feedback-form-star ${rating >= value ? 'active' : ''}`}
                onClick={() => handleRatingChange(value)}
                aria-label={`Rate ${value} out of 5 stars`}
                title={`${value} star${value !== 1 ? 's' : ''}`}
              >
                ★
              </button>
            ))}
            {rating > 0 && (
              <span className="feedback-form-rating-text">{rating} out of 5</span>
            )}
          </div>
        </div>

        {/* Category Field */}
        <div className="feedback-form-field">
          <label htmlFor="category" className="feedback-form-label">
            Feedback Category <span className="optional">(Optional)</span>
          </label>
          <select
            id="category"
            value={category}
            onChange={(e) => setCategory(e.target.value as any)}
            className="feedback-form-input feedback-form-select"
            aria-describedby="category-help"
          >
            <option value="general">General Feedback</option>
            <option value="bug">Bug Report</option>
            <option value="feature-request">Feature Request</option>
            <option value="other">Other</option>
          </select>
          <p id="category-help" className="feedback-form-help-text">
            Help us categorize your feedback
          </p>
        </div>

        {/* Message Field */}
        <div className="feedback-form-field">
          <label htmlFor="message" className="feedback-form-label">
            Your Feedback <span className="required">*</span>
          </label>
          <textarea
            id="message"
            value={message}
            onChange={handleMessageChange}
            placeholder="Please share your thoughts, suggestions, or report any issues..."
            className="feedback-form-textarea"
            rows={6}
            maxLength={maxCharacters}
            required
            aria-describedby="message-help message-count"
          />
          <div id="message-count" className="feedback-form-character-count">
            <div className="feedback-form-character-progress">
              <div
                className="feedback-form-character-progress-bar"
                style={{
                  width: `${characterPercentage}%`,
                  backgroundColor: characterPercentage > 90 ? '#ff6b6b' : '#4CAF50'
                }}
              />
            </div>
            <span>{characterCount} / {maxCharacters} characters</span>
          </div>
          <p id="message-help" className="feedback-form-help-text">
            Be specific and descriptive to help us understand your feedback better
          </p>
        </div>

        {/* Contact Info Field */}
        <div className="feedback-form-field">
          <label htmlFor="contactInfo" className="feedback-form-label">
            Contact Information <span className="optional">(Optional)</span>
          </label>
          <input
            id="contactInfo"
            type="email"
            value={contactInfo}
            onChange={(e) => setContactInfo(e.target.value)}
            placeholder="Your email or phone number (if you'd like us to follow up)"
            className="feedback-form-input"
            aria-describedby="contact-help"
          />
          <p id="contact-help" className="feedback-form-help-text">
            Provide this if you'd like us to contact you regarding your feedback
          </p>
        </div>

        {/* Submit Button */}
        <div className="feedback-form-actions">
          <button
            type="submit"
            disabled={isSubmitting || rating === 0 || message.trim().length === 0}
            className="feedback-form-button feedback-form-button--primary"
            aria-busy={isSubmitting}
          >
            {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
          </button>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="feedback-form-button feedback-form-button--secondary"
              disabled={isSubmitting}
            >
              Cancel
            </button>
          )}
        </div>

        <p className="feedback-form-privacy-notice">
          Your feedback is important to us. We will use it to improve your experience. 
          Any personal information you provide will be handled securely and privately.
        </p>
      </form>
    </div>
  );
};
