import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FeedbackForm } from './FeedbackForm';
import '@testing-library/jest-dom';

describe('FeedbackForm', () => {
  const mockUserId = 'test-user-123';
  const mockOnSubmitSuccess = jest.fn();
  const mockOnSubmitError = jest.fn();
  const mockOnClose = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the feedback form', () => {
    render(<FeedbackForm userId={mockUserId} />);
    expect(screen.getByText('Send Us Your Feedback')).toBeInTheDocument();
  });

  it('renders all required form fields', () => {
    render(<FeedbackForm userId={mockUserId} />);
    expect(screen.getByLabelText(/How would you rate your experience/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Feedback Category/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Your Feedback/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Contact Information/i)).toBeInTheDocument();
  });

  it('renders rating stars', () => {
    render(<FeedbackForm userId={mockUserId} />);
    const stars = screen.getAllByRole('button', { name: /Rate.*out of 5 stars/i });
    expect(stars).toHaveLength(5);
  });

  it('allows user to select a rating', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const fourthStar = screen.getByRole('button', { name: /Rate 4 out of 5 stars/i });
    await user.click(fourthStar);
    
    expect(screen.getByText(/4 out of 5/i)).toBeInTheDocument();
  });

  it('allows user to enter feedback message', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const messageInput = screen.getByLabelText(/Your Feedback/i) as HTMLTextAreaElement;
    await user.type(messageInput, 'This is great feedback!');
    
    expect(messageInput.value).toBe('This is great feedback!');
  });

  it('displays character count', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const messageInput = screen.getByLabelText(/Your Feedback/i);
    await user.type(messageInput, 'Hello');
    
    expect(screen.getByText(/5 \/ 5000 characters/)).toBeInTheDocument();
  });

  it('allows user to select a category', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const categorySelect = screen.getByLabelText(/Feedback Category/i) as HTMLSelectElement;
    await user.selectOptions(categorySelect, 'bug');
    
    expect(categorySelect.value).toBe('bug');
  });

  it('allows user to enter contact information', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const contactInput = screen.getByLabelText(/Contact Information/i) as HTMLInputElement;
    await user.type(contactInput, 'test@example.com');
    
    expect(contactInput.value).toBe('test@example.com');
  });

  it('disables submit button when rating is not selected', () => {
    render(<FeedbackForm userId={mockUserId} />);
    
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i }) as HTMLButtonElement;
    expect(submitButton).toBeDisabled();
  });

  it('disables submit button when message is empty', () => {
    render(<FeedbackForm userId={mockUserId} />);
    
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i }) as HTMLButtonElement;
    expect(submitButton).toBeDisabled();
  });

  it('enables submit button when rating and message are provided', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    // Select rating
    const star = screen.getByRole('button', { name: /Rate 3 out of 5 stars/i });
    await user.click(star);
    
    // Enter message
    const messageInput = screen.getByLabelText(/Your Feedback/i);
    await user.type(messageInput, 'Test feedback');
    
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i }) as HTMLButtonElement;
    expect(submitButton).not.toBeDisabled();
  });

  it('shows error messages for validation failures', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} onSubmitError={mockOnSubmitError} />);
    
    // Try to submit without rating and message
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i });
    
    // Select only rating, no message
    const star = screen.getByRole('button', { name: /Rate 3 out of 5 stars/i });
    await user.click(star);
    
    // Button should still be disabled because message is empty
    expect(submitButton).toBeDisabled();
  });

  it('closes form when close button is clicked', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} onClose={mockOnClose} />);
    
    const closeButton = screen.getByLabelText(/Close feedback form/i);
    await user.click(closeButton);
    
    expect(mockOnClose).toHaveBeenCalled();
  });

  it('closes form when cancel button is clicked', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} onClose={mockOnClose} />);
    
    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    await user.click(cancelButton);
    
    expect(mockOnClose).toHaveBeenCalled();
  });

  it('shows success message after successful submission', async () => {
    const user = userEvent.setup();
    render(
      <FeedbackForm
        userId={mockUserId}
        onSubmitSuccess={mockOnSubmitSuccess}
        onClose={mockOnClose}
      />
    );
    
    // Select rating
    const star = screen.getByRole('button', { name: /Rate 5 out of 5 stars/i });
    await user.click(star);
    
    // Enter message
    const messageInput = screen.getByLabelText(/Your Feedback/i);
    await user.type(messageInput, 'Excellent app!');
    
    // Submit form
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i });
    await user.click(submitButton);
    
    // Wait for success message
    await waitFor(() => {
      expect(screen.getByText(/Thank you! Your feedback has been submitted successfully/i)).toBeInTheDocument();
    });
  });

  it('resets form after successful submission', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    // Select rating
    const star = screen.getByRole('button', { name: /Rate 4 out of 5 stars/i });
    await user.click(star);
    
    // Enter message
    const messageInput = screen.getByLabelText(/Your Feedback/i) as HTMLTextAreaElement;
    await user.type(messageInput, 'Good feedback');
    
    // Submit form
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i });
    await user.click(submitButton);
    
    // Wait for form to reset
    await waitFor(() => {
      expect(messageInput.value).toBe('');
      expect(screen.getByText(/0 \/ 5000 characters/)).toBeInTheDocument();
    });
  });

  it('prevents submission with invalid message length', async () => {
    const user = userEvent.setup();
    render(<FeedbackForm userId={mockUserId} />);
    
    const messageInput = screen.getByLabelText(/Your Feedback/i) as HTMLTextAreaElement;
    
    // Try to enter a message longer than the textarea allows (it should be truncated)
    const longMessage = 'a'.repeat(5001);
    
    // The textarea maxLength should prevent this
    expect(messageInput.maxLength).toBe(5000);
  });

  it('renders privacy notice', () => {
    render(<FeedbackForm userId={mockUserId} />);
    expect(screen.getByText(/Your feedback is important to us/i)).toBeInTheDocument();
  });

  it('has proper accessibility attributes', () => {
    render(<FeedbackForm userId={mockUserId} />);
    
    const form = screen.getByRole('form', { hidden: true }) || screen.getByText(/Send Us Your Feedback/i).closest('form');
    expect(form).toBeInTheDocument();
    
    const labels = screen.getAllByText(/\*/);
    expect(labels.length).toBeGreaterThan(0);
  });
});
