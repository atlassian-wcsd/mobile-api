import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { FeedbackForm } from '../FeedbackForm';
import { FeedbackType } from '../../models/Feedback';

// Mock the FeedbackService
jest.mock('../../services/FeedbackService', () => ({
  FeedbackService: jest.fn().mockImplementation(() => ({
    submitFeedback: jest.fn().mockResolvedValue({
      success: true,
      feedbackId: 'test-feedback-id',
      message: 'Feedback submitted successfully'
    })
  })),
  FeedbackUtils: {
    getFeedbackTypeLabel: (type: FeedbackType) => {
      const labels: Record<FeedbackType, string> = {
        [FeedbackType.BUG_REPORT]: 'Bug Report',
        [FeedbackType.FEATURE_REQUEST]: 'Feature Request',
        [FeedbackType.GENERAL_FEEDBACK]: 'General Feedback',
        [FeedbackType.USABILITY_ISSUE]: 'Usability Issue',
        [FeedbackType.PERFORMANCE_ISSUE]: 'Performance Issue',
        [FeedbackType.OTHER]: 'Other'
      };
      return labels[type] || 'Unknown';
    }
  }
}));

describe('FeedbackForm', () => {
  const defaultProps = {
    isOpen: true,
    onClose: jest.fn(),
    onSuccess: jest.fn(),
    onError: jest.fn()
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders feedback form when open', () => {
    render(<FeedbackForm {...defaultProps} />);
    
    expect(screen.getByText('Send Feedback')).toBeInTheDocument();
    expect(screen.getByLabelText(/subject/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/message/i)).toBeInTheDocument();
    expect(screen.getByText('Submit Feedback')).toBeInTheDocument();
  });

  test('does not render when closed', () => {
    render(<FeedbackForm {...defaultProps} isOpen={false} />);
    
    expect(screen.queryByText('Send Feedback')).not.toBeInTheDocument();
  });

  test('validates required fields', async () => {
    render(<FeedbackForm {...defaultProps} />);
    
    const submitButton = screen.getByText('Submit Feedback');
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Subject is required')).toBeInTheDocument();
      expect(screen.getByText('Message is required')).toBeInTheDocument();
    });
  });

  test('submits form with valid data', async () => {
    const onSuccess = jest.fn();
    render(<FeedbackForm {...defaultProps} onSuccess={onSuccess} />);
    
    // Fill in required fields
    fireEvent.change(screen.getByLabelText(/subject/i), {
      target: { value: 'Test Subject' }
    });
    fireEvent.change(screen.getByLabelText(/message/i), {
      target: { value: 'Test message content' }
    });

    // Submit form
    fireEvent.click(screen.getByText('Submit Feedback'));

    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalledWith('test-feedback-id');
    });
  });

  test('displays character count for subject and message', () => {
    render(<FeedbackForm {...defaultProps} />);
    
    expect(screen.getByText('0/200')).toBeInTheDocument(); // Subject counter
    expect(screen.getByText('0/2000')).toBeInTheDocument(); // Message counter
  });

  test('updates character count when typing', () => {
    render(<FeedbackForm {...defaultProps} />);
    
    const subjectInput = screen.getByLabelText(/subject/i);
    fireEvent.change(subjectInput, { target: { value: 'Test' } });
    
    expect(screen.getByText('4/200')).toBeInTheDocument();
  });

  test('allows rating selection', () => {
    render(<FeedbackForm {...defaultProps} />);
    
    const starButtons = screen.getAllByLabelText(/Rate \d stars/);
    expect(starButtons).toHaveLength(5);
    
    // Click 3rd star
    fireEvent.click(starButtons[2]);
    expect(screen.getByText('3 of 5 stars')).toBeInTheDocument();
  });

  test('pre-fills user information when provided', () => {
    const userInfo = {
      email: 'test@example.com',
      name: 'Test User'
    };
    
    render(<FeedbackForm {...defaultProps} userInfo={userInfo} />);
    
    expect(screen.getByDisplayValue('test@example.com')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Test User')).toBeInTheDocument();
  });

  test('validates email format', async () => {
    render(<FeedbackForm {...defaultProps} />);
    
    const emailInput = screen.getByLabelText(/email/i);
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
    
    // Fill required fields
    fireEvent.change(screen.getByLabelText(/subject/i), {
      target: { value: 'Test Subject' }
    });
    fireEvent.change(screen.getByLabelText(/message/i), {
      target: { value: 'Test message' }
    });
    
    fireEvent.click(screen.getByText('Submit Feedback'));

    await waitFor(() => {
      expect(screen.getByText('Invalid email format')).toBeInTheDocument();
    });
  });

  test('enforces character limits', async () => {
    render(<FeedbackForm {...defaultProps} />);
    
    const longSubject = 'a'.repeat(201);
    const longMessage = 'a'.repeat(2001);
    
    fireEvent.change(screen.getByLabelText(/subject/i), {
      target: { value: longSubject }
    });
    fireEvent.change(screen.getByLabelText(/message/i), {
      target: { value: longMessage }
    });
    
    fireEvent.click(screen.getByText('Submit Feedback'));

    await waitFor(() => {
      expect(screen.getByText('Subject must be 200 characters or less')).toBeInTheDocument();
      expect(screen.getByText('Message must be 2000 characters or less')).toBeInTheDocument();
    });
  });

  test('closes form when close button is clicked', () => {
    const onClose = jest.fn();
    render(<FeedbackForm {...defaultProps} onClose={onClose} />);
    
    fireEvent.click(screen.getByLabelText('Close feedback form'));
    expect(onClose).toHaveBeenCalled();
  });

  test('renders as inline form when modal=false', () => {
    render(<FeedbackForm {...defaultProps} modal={false} />);
    
    // Should not have overlay styles when not modal
    const form = screen.getByText('Send Feedback').closest('div');
    expect(form).not.toHaveStyle('position: fixed');
  });
});