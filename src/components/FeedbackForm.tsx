import React, { useState, useEffect } from 'react';
import { FeedbackType, FeedbackCategory, FeedbackRequest, FeedbackValidator } from '../models/Feedback';
import { feedbackService } from '../services/FeedbackService';

interface FeedbackFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (feedbackId: string) => void;
  onError?: (error: string) => void;
  authToken?: string;
  userEmail?: string;
  className?: string;
}

export const FeedbackForm: React.FC<FeedbackFormProps> = ({
  isOpen,
  onClose,
  onSuccess,
  onError,
  authToken,
  userEmail,
  className = ''
}) => {
  const [formData, setFormData] = useState<FeedbackRequest>({
    type: FeedbackType.GENERAL_FEEDBACK,
    category: FeedbackCategory.GENERAL,
    subject: '',
    message: '',
    rating: undefined,
    email: userEmail || ''
  });

  const [errors, setErrors] = useState<string[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [attachments, setAttachments] = useState<File[]>([]);

  // Reset form when opened
  useEffect(() => {
    if (isOpen) {
      setFormData({
        type: FeedbackType.GENERAL_FEEDBACK,
        category: FeedbackCategory.GENERAL,
        subject: '',
        message: '',
        rating: undefined,
        email: userEmail || ''
      });
      setErrors([]);
      setShowSuccess(false);
      setAttachments([]);
    }
  }, [isOpen, userEmail]);

  const handleInputChange = (field: keyof FeedbackRequest, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear errors when user starts typing
    if (errors.length > 0) {
      setErrors([]);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    const validFiles = files.filter(file => {
      const maxSize = 5 * 1024 * 1024; // 5MB
      const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'];
      
      if (file.size > maxSize) {
        setErrors(prev => [...prev, `File ${file.name} is too large (max 5MB)`]);
        return false;
      }
      
      if (!allowedTypes.includes(file.type)) {
        setErrors(prev => [...prev, `File ${file.name} has unsupported format`]);
        return false;
      }
      
      return true;
    });

    setAttachments(prev => [...prev, ...validFiles].slice(0, 3)); // Max 3 files
  };

  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    // Validate form
    const validationErrors = FeedbackValidator.validateFeedbackRequest(formData);
    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    setIsSubmitting(true);
    setErrors([]);

    try {
      // Upload attachments first
      const attachmentUrls: string[] = [];
      for (const file of attachments) {
        const url = await feedbackService.uploadAttachment(file, authToken);
        if (url) {
          attachmentUrls.push(url);
        }
      }

      // Prepare feedback request with metadata
      const feedbackRequest: FeedbackRequest = {
        ...formData,
        metadata: {
          currentPage: window.location.pathname,
          sessionId: sessionStorage.getItem('sessionId') || undefined,
          errorLogs: feedbackService.collectErrorLogs(),
          attachments: attachmentUrls.length > 0 ? attachmentUrls : undefined
        }
      };

      const response = await feedbackService.submitFeedback(feedbackRequest, authToken);

      if (response.success && response.feedbackId) {
        setShowSuccess(true);
        onSuccess?.(response.feedbackId);
        
        // Auto-close after 3 seconds
        setTimeout(() => {
          onClose();
        }, 3000);
      } else {
        setErrors([response.error || response.message || 'Failed to submit feedback']);
        onError?.(response.error || 'Failed to submit feedback');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An unexpected error occurred';
      setErrors([errorMessage]);
      onError?.(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderStarRating = () => {
    return (
      <div className="star-rating">
        <label>Rating (optional):</label>
        <div className="stars">
          {[1, 2, 3, 4, 5].map(star => (
            <button
              key={star}
              type="button"
              className={`star ${formData.rating && formData.rating >= star ? 'filled' : ''}`}
              onClick={() => handleInputChange('rating', star)}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '24px',
                color: formData.rating && formData.rating >= star ? '#ffd700' : '#ddd',
                cursor: 'pointer',
                padding: '2px'
              }}
            >
              ★
            </button>
          ))}
          {formData.rating && (
            <button
              type="button"
              onClick={() => handleInputChange('rating', undefined)}
              style={{
                background: 'none',
                border: 'none',
                marginLeft: '10px',
                color: '#666',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              Clear
            </button>
          )}
        </div>
      </div>
    );
  };

  if (!isOpen) return null;

  return (
    <div className={`feedback-modal-overlay ${className}`} style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div className="feedback-modal" style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '24px',
        maxWidth: '500px',
        width: '90%',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.15)'
      }}>
        {showSuccess ? (
          <div className="success-message" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '48px', color: '#4CAF50', marginBottom: '16px' }}>✓</div>
            <h3 style={{ color: '#4CAF50', marginBottom: '8px' }}>Feedback Submitted!</h3>
            <p style={{ color: '#666', marginBottom: '16px' }}>
              Thank you for your feedback. We'll review it and get back to you if needed.
            </p>
            <button
              onClick={onClose}
              style={{
                backgroundColor: '#4CAF50',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                padding: '8px 16px',
                cursor: 'pointer'
              }}
            >
              Close
            </button>
          </div>
        ) : (
          <>
            <div className="modal-header" style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px'
            }}>
              <h2 style={{ margin: 0, color: '#333' }}>Send Feedback</h2>
              <button
                onClick={onClose}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '24px',
                  cursor: 'pointer',
                  color: '#666'
                }}
              >
                ×
              </button>
            </div>

            {errors.length > 0 && (
              <div className="error-messages" style={{
                backgroundColor: '#ffebee',
                border: '1px solid #f44336',
                borderRadius: '4px',
                padding: '12px',
                marginBottom: '16px'
              }}>
                {errors.map((error, index) => (
                  <div key={index} style={{ color: '#d32f2f', fontSize: '14px' }}>
                    {error}
                  </div>
                ))}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Feedback Type:
                </label>
                <select
                  value={formData.type}
                  onChange={(e) => handleInputChange('type', e.target.value as FeedbackType)}
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                >
                  <option value={FeedbackType.GENERAL_FEEDBACK}>General Feedback</option>
                  <option value={FeedbackType.BUG_REPORT}>Bug Report</option>
                  <option value={FeedbackType.FEATURE_REQUEST}>Feature Request</option>
                  <option value={FeedbackType.SUPPORT_REQUEST}>Support Request</option>
                  <option value={FeedbackType.COMPLIMENT}>Compliment</option>
                  <option value={FeedbackType.COMPLAINT}>Complaint</option>
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Category:
                </label>
                <select
                  value={formData.category}
                  onChange={(e) => handleInputChange('category', e.target.value as FeedbackCategory)}
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                >
                  <option value={FeedbackCategory.GENERAL}>General</option>
                  <option value={FeedbackCategory.USER_INTERFACE}>User Interface</option>
                  <option value={FeedbackCategory.PERFORMANCE}>Performance</option>
                  <option value={FeedbackCategory.AUTHENTICATION}>Authentication</option>
                  <option value={FeedbackCategory.SIGNATURE_FUNCTIONALITY}>Signature Functionality</option>
                  <option value={FeedbackCategory.APPLE_LOGIN}>Apple Login</option>
                  <option value={FeedbackCategory.OTHER}>Other</option>
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Subject: <span style={{ color: '#f44336' }}>*</span>
                </label>
                <input
                  type="text"
                  value={formData.subject}
                  onChange={(e) => handleInputChange('subject', e.target.value)}
                  placeholder="Brief description of your feedback"
                  maxLength={100}
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                />
                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                  {formData.subject.length}/100 characters
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Message: <span style={{ color: '#f44336' }}>*</span>
                </label>
                <textarea
                  value={formData.message}
                  onChange={(e) => handleInputChange('message', e.target.value)}
                  placeholder="Please provide detailed feedback..."
                  rows={5}
                  maxLength={2000}
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px',
                    resize: 'vertical'
                  }}
                />
                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                  {formData.message.length}/2000 characters
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                {renderStarRating()}
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Contact Email (optional):
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleInputChange('email', e.target.value)}
                  placeholder="your.email@example.com"
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                />
                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                  We'll only use this to follow up on your feedback
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '4px', fontWeight: '500' }}>
                  Attachments (optional):
                </label>
                <input
                  type="file"
                  multiple
                  accept="image/*,.pdf,.txt"
                  onChange={handleFileUpload}
                  style={{
                    width: '100%',
                    padding: '8px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                />
                <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
                  Max 3 files, 5MB each. Supported: images, PDF, text files
                </div>
                
                {attachments.length > 0 && (
                  <div style={{ marginTop: '8px' }}>
                    {attachments.map((file, index) => (
                      <div key={index} style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '4px 8px',
                        backgroundColor: '#f5f5f5',
                        borderRadius: '4px',
                        marginBottom: '4px'
                      }}>
                        <span style={{ fontSize: '12px' }}>{file.name}</span>
                        <button
                          type="button"
                          onClick={() => removeAttachment(index)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#f44336',
                            cursor: 'pointer',
                            fontSize: '12px'
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="form-actions" style={{
                display: 'flex',
                justifyContent: 'flex-end',
                gap: '12px'
              }}>
                <button
                  type="button"
                  onClick={onClose}
                  disabled={isSubmitting}
                  style={{
                    padding: '10px 20px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    backgroundColor: 'white',
                    color: '#666',
                    cursor: isSubmitting ? 'not-allowed' : 'pointer',
                    fontSize: '14px'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  style={{
                    padding: '10px 20px',
                    border: 'none',
                    borderRadius: '4px',
                    backgroundColor: isSubmitting ? '#ccc' : '#007bff',
                    color: 'white',
                    cursor: isSubmitting ? 'not-allowed' : 'pointer',
                    fontSize: '14px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  {isSubmitting && (
                    <div style={{
                      width: '16px',
                      height: '16px',
                      border: '2px solid #ffffff40',
                      borderTop: '2px solid #ffffff',
                      borderRadius: '50%',
                      animation: 'spin 1s linear infinite'
                    }} />
                  )}
                  {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  );
};

export default FeedbackForm;