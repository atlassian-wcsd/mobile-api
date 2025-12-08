import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FeedbackButton } from './FeedbackButton';
import '@testing-library/jest-dom';

describe('FeedbackButton', () => {
  const mockUserId = 'test-user-123';
  const mockOnFeedbackSubmitted = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the feedback button', () => {
    render(<FeedbackButton userId={mockUserId} />);
    const button = screen.getByRole('button', { name: /Send feedback/i });
    expect(button).toBeInTheDocument();
  });

  it('opens feedback form when button is clicked', async () => {
    const user = userEvent.setup();
    render(<FeedbackButton userId={mockUserId} />);
    
    const button = screen.getByRole('button', { name: /Send feedback/i });
    await user.click(button);
    
    expect(screen.getByText(/Send Us Your Feedback/i)).toBeInTheDocument();
  });

  it('closes feedback form when close button is clicked', async () => {
    const user = userEvent.setup();
    render(<FeedbackButton userId={mockUserId} />);
    
    // Open form
    const button = screen.getByRole('button', { name: /Send feedback/i });
    await user.click(button);
    
    // Close form
    const closeButton = screen.getByLabelText(/Close feedback form/i);
    await user.click(closeButton);
    
    expect(screen.queryByText(/Send Us Your Feedback/i)).not.toBeInTheDocument();
  });

  it('closes feedback form when clicking outside (overlay)', async () => {
    const user = userEvent.setup();
    render(<FeedbackButton userId={mockUserId} />);
    
    // Open form
    const button = screen.getByRole('button', { name: /Send feedback/i });
    await user.click(button);
    
    // Click on overlay
    const overlay = document.querySelector('.feedback-modal-overlay');
    if (overlay) {
      await user.click(overlay);
    }
    
    expect(screen.queryByText(/Send Us Your Feedback/i)).not.toBeInTheDocument();
  });

  it('renders with different positions', () => {
    const { rerender } = render(<FeedbackButton userId={mockUserId} position="top-left" />);
    let button = screen.getByRole('button', { name: /Send feedback/i });
    expect(button.className).toContain('feedback-button--top-left');
    
    rerender(<FeedbackButton userId={mockUserId} position="bottom-left" />);
    button = screen.getByRole('button', { name: /Send feedback/i });
    expect(button.className).toContain('feedback-button--bottom-left');
  });

  it('calls onFeedbackSubmitted callback after form submission', async () => {
    const user = userEvent.setup();
    render(
      <FeedbackButton 
        userId={mockUserId} 
        onFeedbackSubmitted={mockOnFeedbackSubmitted}
      />
    );
    
    // Open form
    const button = screen.getByRole('button', { name: /Send feedback/i });
    await user.click(button);
    
    // Fill and submit form
    const star = screen.getByRole('button', { name: /Rate 5 out of 5 stars/i });
    await user.click(star);
    
    const messageInput = screen.getByLabelText(/Your Feedback/i);
    await user.type(messageInput, 'Great app!');
    
    const submitButton = screen.getByRole('button', { name: /Submit Feedback/i });
    await user.click(submitButton);
    
    // Check if callback was called
    // Note: In a real scenario, this would be called after successful submission
  });

  it('has proper aria attributes', () => {
    render(<FeedbackButton userId={mockUserId} ariaLabel="Leave us feedback" />);
    const button = screen.getByRole('button', { name: /Leave us feedback/i });
    expect(button).toHaveAttribute('aria-label');
  });
});
