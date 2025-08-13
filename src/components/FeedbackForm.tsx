import React, { useState, useRef } from 'react';
import { FeedbackCategory, FeedbackSubmissionRequest, FeedbackValidator } from '../models/Feedback';
import { FeedbackService, FeedbackServiceUtils } from '../services/FeedbackService';

interface FeedbackFormProps {
  onSuccess?: (feedbackId: string) => void;
  onError?: (error: string) => void;
  onClose?: () => void;
  userEmail?: string;
  className?: string;
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  onSuccess,
  onError,
  onClose,
  userEmail,
  className = ''
}) => {
  const [formData, setFormData] = useState<FeedbackSubmissionRequest>({
    rating: 5,
    category: FeedbackCategory.GENERAL_FEEDBACK,
    subject: '',
    message: '',
    email: userEmail || '',
    attachments: []
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [attachments, setAttachments] = useState<File[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const feedbackService = new FeedbackService();

  const handleInputChange = (field: keyof FeedbackSubmissionRequest, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear errors when user starts typing
    if (errors.length > 0) {
      setErrors([]);
    }
  };

  const handleRatingChange = (rating: number) => {
    handleInputChange('rating', rating);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    const validFiles: File[] = [];
    const fileErrors: string[] = [];

    files.forEach(file => {
      const error = FeedbackServiceUtils.validateAttachment(file);
      if (error) {
        fileErrors.push(`${file.name}: ${error}`);
      } else {
        validFiles.push(file);
      }
    });

    if (fileErrors.length > 0) {
      setErrors(fileErrors);
      return;
    }

    setAttachments(prev => [...prev, ...validFiles]);
    
    // Clear the input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    // Validate form
    const validationErrors = FeedbackValidator.validateFeedback(formData);
    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    setIsSubmitting(true);
    setErrors([]);

    try {
      // Submit feedback
      const response = await feedbackService.submitFeedback({
        ...formData,
        attachments
      });

      if (response.success && response.feedbackId) {
        onSuccess?.(response.feedbackId);
        // Reset form
        setFormData({
          rating: 5,
          category: FeedbackCategory.GENERAL_FEEDBACK,
          subject: '',
          message: '',
          email: userEmail || '',
          attachments: []
        });
        setAttachments([]);
      } else {
        onError?.(response.error || 'Failed to submit feedback');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to submit feedback';
      onError?.(errorMessage);
      setErrors([errorMessage]);
    } finally {
      setIsSubmitting(false);
    }
  };

  const StarRating: React.FC<{ rating: number; onRatingChange: (rating: number) => void }> = ({
    rating,
    onRatingChange
  }) => {
    return (
      <div style={{ display: 'flex', gap: '4px' }}>
        {[1, 2, 3, 4, 5].map((star) => (
          <button
            key={star}
            type="button"
            onClick={() => onRatingChange(star)}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '24px',
              cursor: 'pointer',
              color: star <= rating ? '#ffd700' : '#ddd',
              padding: '0',
              transition: 'color 0.2s ease'
            }}
            onMouseEnter={(e) => {
              if (!isSubmitting) {
                e.currentTarget.style.color = '#ffd700';
              }
            }}
            onMouseLeave={(e) => {
              if (!isSubmitting) {
                e.currentTarget.style.color = star <= rating ? '#ffd700' : '#ddd';
              }
            }}
          >
            ★
          </button>
        ))}
        <span style={{ marginLeft: '8px', fontSize: '14px', color: '#666' }}>
          ({rating}/5)
        </span>
      </div>
    );
  };

  return (
    <div className={`feedback-form ${className}`} style={{
      maxWidth: '600px',
      margin: '0 auto',
      padding: '24px',
      backgroundColor: '#fff',
      borderRadius: '8px',
      boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)',
      border: '1px solid #e0e0e0'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h2 style={{ margin: '0', fontSize: '24px', fontWeight: '600', color: '#333' }}>
          Share Your Feedback
        </h2>
        {onClose && (
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '24px',
              cursor: 'pointer',
              color: '#666',
              padding: '0',
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            ×
          </button>
        )}
      </div>

      {errors.length > 0 && (
        <div style={{
          backgroundColor: '#fee',
          border: '1px solid #fcc',
          borderRadius: '4px',
          padding: '12px',
          marginBottom: '16px'
        }}>
          {errors.map((error, index) => (
            <div key={index} style={{ color: '#c33', fontSize: '14px' }}>
              {error}
            </div>
          ))}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Rating */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Overall Rating *
          </label>
          <StarRating rating={formData.rating} onRatingChange={handleRatingChange} />
        </div>

        {/* Category */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Category *
          </label>
          <select
            value={formData.category}
            onChange={(e) => handleInputChange('category', e.target.value as FeedbackCategory)}
            disabled={isSubmitting}
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid #ddd',
              borderRadius: '4px',
              fontSize: '16px',
              backgroundColor: isSubmitting ? '#f5f5f5' : '#fff'
            }}
          >
            {feedbackService.getFeedbackCategories().map(category => (
              <option key={category.value} value={category.value}>
                {category.label}
              </option>
            ))}
          </select>
        </div>

        {/* Subject */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Subject *
          </label>
          <input
            type="text"
            value={formData.subject}
            onChange={(e) => handleInputChange('subject', e.target.value)}
            placeholder="Brief description of your feedback"
            disabled={isSubmitting}
            maxLength={100}
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid #ddd',
              borderRadius: '4px',
              fontSize: '16px',
              backgroundColor: isSubmitting ? '#f5f5f5' : '#fff'
            }}
          />
          <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
            {formData.subject.length}/100 characters
          </div>
        </div>

        {/* Message */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Message *
          </label>
          <textarea
            value={formData.message}
            onChange={(e) => handleInputChange('message', e.target.value)}
            placeholder="Please provide detailed feedback..."
            disabled={isSubmitting}
            maxLength={2000}
            rows={6}
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid #ddd',
              borderRadius: '4px',
              fontSize: '16px',
              backgroundColor: isSubmitting ? '#f5f5f5' : '#fff',
              resize: 'vertical',
              minHeight: '120px'
            }}
          />
          <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
            {formData.message.length}/2000 characters
          </div>
        </div>

        {/* Email */}
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Email (optional)
          </label>
          <input
            type="email"
            value={formData.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            placeholder="your.email@example.com"
            disabled={isSubmitting}
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid #ddd',
              borderRadius: '4px',
              fontSize: '16px',
              backgroundColor: isSubmitting ? '#f5f5f5' : '#fff'
            }}
          />
          <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
            We'll use this to follow up on your feedback
          </div>
        </div>

        {/* File Attachments */}
        <div style={{ marginBottom: '24px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500', color: '#333' }}>
            Attachments (optional)
          </label>
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileUpload}
            multiple
            accept=".jpg,.jpeg,.png,.gif,.txt,.pdf"
            disabled={isSubmitting}
            style={{ display: 'none' }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isSubmitting}
            style={{
              padding: '8px 16px',
              border: '1px solid #ddd',
              borderRadius: '4px',
              backgroundColor: '#f8f9fa',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              fontSize: '14px'
            }}
          >
            Choose Files
          </button>
          <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
            Supported: JPEG, PNG, GIF, TXT, PDF (max 5MB each)
          </div>
          
          {attachments.length > 0 && (
            <div style={{ marginTop: '8px' }}>
              {attachments.map((file, index) => (
                <div key={index} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px',
                  backgroundColor: '#f0f0f0',
                  borderRadius: '4px',
                  marginBottom: '4px'
                }}>
                  <span style={{ fontSize: '14px' }}>{file.name}</span>
                  <button
                    type="button"
                    onClick={() => removeAttachment(index)}
                    disabled={isSubmitting}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#c33',
                      cursor: isSubmitting ? 'not-allowed' : 'pointer',
                      fontSize: '16px'
                    }}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Submit Button */}
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              style={{
                padding: '12px 24px',
                border: '1px solid #ddd',
                borderRadius: '4px',
                backgroundColor: '#fff',
                color: '#333',
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                fontSize: '16px'
              }}
            >
              Cancel
            </button>
          )}
          <button
            type="submit"
            disabled={isSubmitting}
            style={{
              padding: '12px 24px',
              border: 'none',
              borderRadius: '4px',
              backgroundColor: isSubmitting ? '#ccc' : '#007bff',
              color: '#fff',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              fontSize: '16px',
              fontWeight: '500',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            {isSubmitting ? (
              <>
                <div style={{
                  width: '16px',
                  height: '16px',
                  border: '2px solid #ffffff40',
                  borderTop: '2px solid #ffffff',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }} />
                Submitting...
              </>
            ) : (
              'Submit Feedback'
            )}
          </button>
        </div>
      </form>

      <style>
        {`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}
      </style>
    </div>
  );
};

export default FeedbackForm;