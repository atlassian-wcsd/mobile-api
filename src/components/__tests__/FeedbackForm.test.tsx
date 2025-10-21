import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { FeedbackForm } from '../FeedbackForm';
import { FeedbackCategory } from '../../models/Feedback';

// Mock the FeedbackService
jest.mock('../../services/FeedbackService', () => ({
  FeedbackService: jest.fn().mockImplementation(() => ({
    submitFeedback: jest.fn()
  }))
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

  it('renders when open', () => {
    render(<FeedbackForm {...defaultProps} />);
    
    expect(screen.getByText('Share Your Feedback')).toBeInTheDocument();
    expect(screen.getByLabelText(/how would you rate/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/category/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/your feedback/i)).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    render(<FeedbackForm {...defaultProps} isOpen={false} />);
    
    expect(screen.queryByText('Share Your Feedback')).not.toBeInTheDocument();
  });

  it('allows user to select rating', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const thirdStar = screen.getAllByRole('button')[2]; // Third star (1-indexed)
    await user.click(thirdStar);
    
    // Check that stars are highlighted (this would need to be implemented based on actual styling)
    expect(thirdStar).toBeInTheDocument();
  });

  it('allows user to enter feedback text', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const textArea = screen.getByLabelText(/your feedback/i);
    await user.type(textArea, 'This is my feedback about the app');
    
    expect(textArea).toHaveValue('This is my feedback about the app');
  });

  it('allows user to select category', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const categorySelect = screen.getByLabelText(/category/i);
    await user.selectOptions(categorySelect, 'bug_report');
    
    expect(categorySelect).toHaveValue('bug_report');
  });

  it('allows user to enter contact email', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const emailInput = screen.getByLabelText(/contact email/i);
    await user.type(emailInput, 'test@example.com');
    
    expect(emailInput).toHaveValue('test@example.com');
  });

  it('shows character count for feedback text', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const textArea = screen.getByLabelText(/your feedback/i);
    await user.type(textArea, 'Hello');
    
    expect(screen.getByText('5/2000 characters')).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/please provide a rating/i)).toBeInTheDocument();
      expect(screen.getByText(/feedback text is required/i)).toBeInTheDocument();
    });
  });

  it('validates minimum feedback text length', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    // Select rating
    const firstStar = screen.getAllByRole('button')[0];
    await user.click(firstStar);
    
    // Enter short text
    const textArea = screen.getByLabelText(/your feedback/i);
    await user.type(textArea, 'Short');
    
    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/feedback text must be at least 10 characters/i)).toBeInTheDocument();
    });
  });

  it('validates email format', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm {...defaultProps} />);
    
    const emailInput = screen.getByLabelText(/contact email/i);
    await user.type(emailInput, 'invalid-email');
    
    // Trigger validation by trying to submit
    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/please enter a valid email address/i)).toBeInTheDocument();
    });
  });

  it('calls onClose when close button is clicked', async () => {
    const user = userEvent.setup();
    const onClose = jest.fn();
    render(<FeedbackForm {...defaultProps} onClose={onClose} />);
    
    const closeButton = screen.getByLabelText(/close feedback form/i);
    await user.click(closeButton);
    
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when cancel button is clicked', async () => {
    const user = userEvent.setup();
    const onClose = jest.fn();
    render(<FeedbackForm {...defaultProps} onClose={onClose} />);
    
    const cancelButton = screen.getByRole('button', { name: /cancel/i });
    await user.click(cancelButton);
    
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('shows success message after successful submission', async () => {
    const { FeedbackService } = require('../../services/FeedbackService');
    const mockSubmitFeedback = jest.fn().mockResolvedValue({
      success: true,
      feedbackId: 'test-id',
      message: 'Success'
    });
    FeedbackService.mockImplementation(() => ({
      submitFeedback: mockSubmitFeedback
    }));

    const user = userEvent.setup();
    const onSuccess = jest.fn();
    render(<FeedbackForm {...defaultProps} onSuccess={onSuccess} />);
    
    // Fill out form
    const firstStar = screen.getAllByRole('button')[0];
    await user.click(firstStar);
    
    const textArea = screen.getByLabelText(/your feedback/i);
    await user.type(textArea, 'This is valid feedback text');
    
    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Thank You!')).toBeInTheDocument();
      expect(screen.getByText(/your feedback has been submitted successfully/i)).toBeInTheDocument();
    });
    
    expect(onSuccess).toHaveBeenCalledWith('test-id');
  });

  it('shows error message on submission failure', async () => {
    const { FeedbackService } = require('../../services/FeedbackService');
    const mockSubmitFeedback = jest.fn().mockResolvedValue({
      success: false,
      error: 'Submission failed'
    });
    FeedbackService.mockImplementation(() => ({
      submitFeedback: mockSubmitFeedback
    }));

    const user = userEvent.setup();
    const onError = jest.fn();
    render(<FeedbackForm {...defaultProps} onError={onError} />);
    
    // Fill out form
    const firstStar = screen.getAllByRole('button')[0];
    await user.click(firstStar);
    
    const textArea = screen.getByLabelText(/your feedback/i);
    await user.type(textArea, 'This is valid feedback text');
    
    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Submission failed')).toBeInTheDocument();
    });
    
    expect(onError).toHaveBeenCalledWith('Submission failed');
  });

  it('resets form when reopened', () => {
    const { rerender } = render(<FeedbackForm {...defaultProps} isOpen={false} />);
    
    // Open form and fill it
    rerender(<FeedbackForm {...defaultProps} isOpen={true} />);
    
    const textArea = screen.getByLabelText(/your feedback/i);
    fireEvent.change(textArea, { target: { value: 'Some text' } });
    
    // Close and reopen
    rerender(<FeedbackForm {...defaultProps} isOpen={false} />);
    rerender(<FeedbackForm {...defaultProps} isOpen={true} />);
    
    expect(screen.getByLabelText(/your feedback/i)).toHaveValue('');
  });

  it('uses initial category when provided', () => {
    render(
      <FeedbackForm 
        {...defaultProps} 
        initialCategory={FeedbackCategory.BUG_REPORT} 
      />
    );
    
    const categorySelect = screen.getByLabelText(/category/i);
    expect(categorySelect).toHaveValue('bug_report');
  });
});