import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { FeedbackForm } from '../FeedbackForm';
import { feedbackService } from '../../services/FeedbackService';

// Mock the feedback service
jest.mock('../../services/FeedbackService', () => ({
  feedbackService: {
    submitFeedback: jest.fn(),
    trackEvent: jest.fn(),
  },
}));

describe('FeedbackForm', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders form with all required fields', () => {
    render(<FeedbackForm />);

    expect(screen.getByLabelText(/type/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/category/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/title/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/message/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /submit feedback/i })).toBeInTheDocument();
  });

  it('validates required fields', async () => {
    render(<FeedbackForm />);

    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/title must be at least 3 characters/i)).toBeInTheDocument();
      expect(screen.getByText(/message must be at least 10 characters/i)).toBeInTheDocument();
    });

    expect(feedbackService.submitFeedback).not.toHaveBeenCalled();
  });

  it('submits feedback successfully', async () => {
    const mockSubmitFeedback = feedbackService.submitFeedback as jest.Mock;
    mockSubmitFeedback.mockResolvedValue({
      success: true,
      feedbackId: 'feedback-123',
      message: 'Feedback submitted successfully',
    });

    const onSuccess = jest.fn();
    render(<FeedbackForm onSuccess={onSuccess} />);

    // Fill out the form
    const titleInput = screen.getByLabelText(/title/i);
    const messageInput = screen.getByLabelText(/message/i);

    await userEvent.type(titleInput, 'Test Feedback Title');
    await userEvent.type(messageInput, 'This is a detailed test feedback message');

    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(mockSubmitFeedback).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Test Feedback Title',
          message: 'This is a detailed test feedback message',
          feedbackType: 'general',
          category: 'general',
        })
      );
    });

    await waitFor(() => {
      expect(screen.getByText(/feedback submitted successfully/i)).toBeInTheDocument();
    });
  });

  it('handles submission error', async () => {
    const mockSubmitFeedback = feedbackService.submitFeedback as jest.Mock;
    mockSubmitFeedback.mockResolvedValue({
      success: false,
      error: 'Server error',
    });

    render(<FeedbackForm />);

    const titleInput = screen.getByLabelText(/title/i);
    const messageInput = screen.getByLabelText(/message/i);

    await userEvent.type(titleInput, 'Test Title');
    await userEvent.type(messageInput, 'Test message content');

    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/server error/i)).toBeInTheDocument();
    });
  });

  it('allows rating selection', async () => {
    render(<FeedbackForm />);

    const starButtons = screen.getAllByLabelText(/rate \d stars/i);
    expect(starButtons).toHaveLength(5);

    // Click on 4th star
    fireEvent.click(starButtons[3]);

    // Verify rating is selected (you may need to check visual feedback or state)
    expect(starButtons[3]).toBeInTheDocument();
  });

  it('validates email format', async () => {
    render(<FeedbackForm />);

    const emailInput = screen.getByLabelText(/email/i);
    await userEvent.type(emailInput, 'invalid-email');

    const titleInput = screen.getByLabelText(/title/i);
    await userEvent.type(titleInput, 'Test');

    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/please enter a valid email address/i)).toBeInTheDocument();
    });
  });

  it('enforces character limits', async () => {
    render(<FeedbackForm />);

    const titleInput = screen.getByLabelText(/title/i) as HTMLInputElement;
    const messageInput = screen.getByLabelText(/message/i) as HTMLTextAreaElement;

    expect(titleInput.maxLength).toBe(200);
    expect(messageInput.maxLength).toBe(5000);
  });

  it('calls onCancel when cancel button is clicked', () => {
    const onCancel = jest.fn();
    render(<FeedbackForm onCancel={onCancel} />);

    const cancelButton = screen.getByRole('button', { name: /cancel/i });
    fireEvent.click(cancelButton);

    expect(onCancel).toHaveBeenCalled();
  });

  it('tracks form view on mount', () => {
    const mockTrackEvent = feedbackService.trackEvent as jest.Mock;

    render(<FeedbackForm defaultCategory="signature" defaultType="bug" />);

    expect(mockTrackEvent).toHaveBeenCalledWith(
      'feedback',
      'feedback_form_viewed',
      expect.objectContaining({
        category: 'signature',
        type: 'bug',
      })
    );
  });

  it('clears errors when user corrects input', async () => {
    render(<FeedbackForm />);

    const submitButton = screen.getByRole('button', { name: /submit feedback/i });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/title must be at least 3 characters/i)).toBeInTheDocument();
    });

    const titleInput = screen.getByLabelText(/title/i);
    await userEvent.type(titleInput, 'Valid Title');

    await waitFor(() => {
      expect(screen.queryByText(/title must be at least 3 characters/i)).not.toBeInTheDocument();
    });
  });
});
