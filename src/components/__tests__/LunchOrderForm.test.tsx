import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { LunchOrderForm } from '../LunchOrderForm';
import { lunchOrderService } from '../../services/LunchOrderService';
import { feedbackService } from '../../services/FeedbackService';

// Mock the services
jest.mock('../../services/LunchOrderService');
jest.mock('../../services/FeedbackService');

describe('LunchOrderForm', () => {
  const mockOnSuccess = jest.fn();
  const mockOnCancel = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();

    // Setup default mock implementations
    (feedbackService.trackEvent as jest.Mock).mockResolvedValue(true);
    (feedbackService.trackError as jest.Mock).mockResolvedValue(undefined);
  });

  describe('Form Rendering', () => {
    it('should render all required form fields', () => {
      render(<LunchOrderForm />);

      expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/menu selection/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/quantity/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/special instructions/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/delivery location/i)).toBeInTheDocument();
      expect(
        screen.getByLabelText(/send me notifications/i)
      ).toBeInTheDocument();
    });

    it('should display submit button', () => {
      render(<LunchOrderForm />);
      expect(screen.getByRole('button', { name: /place order/i })).toBeInTheDocument();
    });

    it('should display cancel button when onCancel is provided', () => {
      render(<LunchOrderForm onCancel={mockOnCancel} />);
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    });

    it('should not display cancel button when onCancel is not provided', () => {
      render(<LunchOrderForm />);
      expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    });

    it('should track form view on mount', () => {
      render(<LunchOrderForm />);
      expect(feedbackService.trackEvent).toHaveBeenCalledWith(
        'lunch_order',
        'order_form_viewed',
        {}
      );
    });
  });

  describe('Field Validation - Inline', () => {
    it('should show error when name field is empty and blurred', async () => {
      render(<LunchOrderForm />);
      const nameInput = screen.getByLabelText(/name/i);

      fireEvent.blur(nameInput);

      await waitFor(() => {
        expect(screen.getByText(/name is required/i)).toBeInTheDocument();
      });
    });

    it('should show error for invalid email format', async () => {
      render(<LunchOrderForm />);
      const emailInput = screen.getByLabelText(/email/i);

      fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
      fireEvent.blur(emailInput);

      await waitFor(() => {
        expect(
          screen.getByText(/please enter a valid email address/i)
        ).toBeInTheDocument();
      });
    });

    it('should not show error for empty email (optional field)', async () => {
      render(<LunchOrderForm />);
      const emailInput = screen.getByLabelText(/email/i);

      fireEvent.blur(emailInput);

      await waitFor(() => {
        expect(
          screen.queryByText(/please enter a valid email address/i)
        ).not.toBeInTheDocument();
      });
    });

    it('should show error when menu selection is empty and blurred', async () => {
      render(<LunchOrderForm />);
      const menuSelect = screen.getByLabelText(/menu selection/i);

      fireEvent.blur(menuSelect);

      await waitFor(() => {
        expect(screen.getByText(/menu selection is required/i)).toBeInTheDocument();
      });
    });

    it('should clear error when user starts typing in name field', async () => {
      render(<LunchOrderForm />);
      const nameInput = screen.getByLabelText(/name/i);

      // Trigger error
      fireEvent.blur(nameInput);
      await waitFor(() => {
        expect(screen.getByText(/name is required/i)).toBeInTheDocument();
      });

      // Start typing to clear error
      fireEvent.change(nameInput, { target: { value: 'John' } });
      await waitFor(() => {
        expect(screen.queryByText(/name is required/i)).not.toBeInTheDocument();
      });
    });

    it('should track validation errors on blur', async () => {
      render(<LunchOrderForm />);
      const nameInput = screen.getByLabelText(/name/i);

      fireEvent.blur(nameInput);

      await waitFor(() => {
        expect(feedbackService.trackEvent).toHaveBeenCalledWith(
          'lunch_order',
          'validation_error',
          expect.objectContaining({
            field: 'name',
          })
        );
      });
    });
  });

  describe('Form Submission - Success', () => {
    it('should submit valid form successfully', async () => {
      const mockResponse = {
        success: true,
        orderId: '12345',
        message: 'Order submitted successfully!',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm onSuccess={mockOnSuccess} />);

      // Fill out form
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.change(screen.getByLabelText(/quantity/i), {
        target: { value: '2' },
      });

      // Submit form
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(lunchOrderService.submitLunchOrder).toHaveBeenCalledWith(
          expect.objectContaining({
            name: 'John Doe',
            menuSelection: 'Pizza',
            quantity: 2,
          })
        );
      });

      await waitFor(() => {
        expect(mockOnSuccess).toHaveBeenCalledWith('12345');
      });

      // Should show success message
      expect(screen.getByText(/order submitted successfully/i)).toBeInTheDocument();
    });

    it('should track submission attempt', async () => {
      const mockResponse = {
        success: true,
        orderId: '12345',
        message: 'Order submitted successfully!',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm />);

      // Fill and submit
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(feedbackService.trackEvent).toHaveBeenCalledWith(
          'lunch_order',
          'order_submit_attempted',
          {}
        );
      });
    });

    it('should track successful submission', async () => {
      const mockResponse = {
        success: true,
        orderId: '12345',
        message: 'Order submitted successfully!',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm />);

      // Fill and submit
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(feedbackService.trackEvent).toHaveBeenCalledWith(
          'lunch_order',
          'order_submit_success',
          { orderId: '12345' }
        );
      });
    });

    it('should reset form after successful submission', async () => {
      const mockResponse = {
        success: true,
        orderId: '12345',
        message: 'Order submitted successfully!',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm />);

      const nameInput = screen.getByLabelText(/name/i) as HTMLInputElement;
      const menuSelect = screen.getByLabelText(/menu selection/i) as HTMLSelectElement;

      // Fill and submit
      fireEvent.change(nameInput, { target: { value: 'John Doe' } });
      fireEvent.change(menuSelect, { target: { value: 'Pizza' } });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(nameInput.value).toBe('');
        expect(menuSelect.value).toBe('');
      });
    });
  });

  describe('Form Submission - Validation Errors', () => {
    it('should prevent submission with empty required fields', async () => {
      render(<LunchOrderForm />);

      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/please correct the errors before submitting/i)
        ).toBeInTheDocument();
      });

      expect(lunchOrderService.submitLunchOrder).not.toHaveBeenCalled();
    });

    it('should track validation failure on submission', async () => {
      render(<LunchOrderForm />);

      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(feedbackService.trackEvent).toHaveBeenCalledWith(
          'lunch_order',
          'order_submit_validation_failed',
          expect.objectContaining({
            errorCount: expect.any(Number),
            errorFields: expect.any(Array),
          })
        );
      });
    });

    it('should display all validation errors on submit attempt', async () => {
      render(<LunchOrderForm />);

      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(screen.getByText(/name is required/i)).toBeInTheDocument();
        expect(screen.getByText(/menu selection is required/i)).toBeInTheDocument();
      });
    });
  });

  describe('Form Submission - Server Errors', () => {
    it('should handle submission error from server', async () => {
      const mockResponse = {
        success: false,
        message: 'Server error',
        error: 'Internal server error',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm />);

      // Fill and submit
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(screen.getByText(/server error/i)).toBeInTheDocument();
      });
    });

    it('should track submission error', async () => {
      const mockResponse = {
        success: false,
        message: 'Server error',
        error: 'Internal server error',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockResolvedValue(
        mockResponse
      );

      render(<LunchOrderForm />);

      // Fill and submit
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(feedbackService.trackEvent).toHaveBeenCalledWith(
          'lunch_order',
          'order_submit_error',
          { error: 'Internal server error' }
        );
      });
    });

    it('should handle network error gracefully', async () => {
      (lunchOrderService.submitLunchOrder as jest.Mock).mockRejectedValue(
        new Error('Network error')
      );

      render(<LunchOrderForm />);

      // Fill and submit
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });
      fireEvent.click(screen.getByRole('button', { name: /place order/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/an unexpected error occurred/i)
        ).toBeInTheDocument();
      });
    });
  });

  describe('Form Abandonment', () => {
    it('should track form abandonment when cancel is clicked with filled fields', () => {
      render(<LunchOrderForm onCancel={mockOnCancel} />);

      // Fill some fields
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });

      // Click cancel
      fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

      expect(feedbackService.trackEvent).toHaveBeenCalledWith(
        'lunch_order',
        'order_form_abandoned',
        expect.objectContaining({
          filledFields: expect.any(Array),
        })
      );
      expect(mockOnCancel).toHaveBeenCalled();
    });

    it('should not track abandonment for empty form', () => {
      render(<LunchOrderForm onCancel={mockOnCancel} />);

      // Click cancel without filling fields
      fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

      // Should not track abandonment for empty form
      expect(feedbackService.trackEvent).not.toHaveBeenCalledWith(
        'lunch_order',
        'order_form_abandoned',
        expect.anything()
      );
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes for errors', async () => {
      render(<LunchOrderForm />);
      const nameInput = screen.getByLabelText(/name/i);

      fireEvent.blur(nameInput);

      await waitFor(() => {
        expect(nameInput).toHaveAttribute('aria-invalid', 'true');
        expect(nameInput).toHaveAttribute('aria-describedby', 'name-error');
      });
    });

    it('should mark error messages with role="alert"', async () => {
      render(<LunchOrderForm />);
      const nameInput = screen.getByLabelText(/name/i);

      fireEvent.blur(nameInput);

      await waitFor(() => {
        const errorMessage = screen.getByText(/name is required/i);
        expect(errorMessage).toHaveAttribute('role', 'alert');
      });
    });
  });

  describe('Submit Button State', () => {
    it('should disable submit button while submitting', async () => {
      const mockResponse = {
        success: true,
        orderId: '12345',
        message: 'Success',
      };
      (lunchOrderService.submitLunchOrder as jest.Mock).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve(mockResponse), 100))
      );

      render(<LunchOrderForm />);

      // Fill form
      fireEvent.change(screen.getByLabelText(/name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/menu selection/i), {
        target: { value: 'Pizza' },
      });

      const submitButton = screen.getByRole('button', { name: /place order/i });
      fireEvent.click(submitButton);

      // Button should be disabled and show "Submitting..."
      await waitFor(() => {
        expect(submitButton).toBeDisabled();
        expect(submitButton).toHaveTextContent(/submitting/i);
      });
    });
  });
});
