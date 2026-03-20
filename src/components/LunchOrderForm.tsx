import React, { useState, useEffect } from 'react';
import { lunchOrderService } from '../services/LunchOrderService';
import { LunchOrderSubmitRequest } from '../models/LunchOrder';
import { feedbackService } from '../services/FeedbackService';

interface LunchOrderFormProps {
  onSuccess?: (orderId: string) => void;
  onCancel?: () => void;
}

export const LunchOrderForm: React.FC<LunchOrderFormProps> = ({
  onSuccess,
  onCancel,
}) => {
  const [formData, setFormData] = useState<LunchOrderSubmitRequest>({
    name: '',
    email: '',
    menuSelection: '',
    specialInstructions: '',
    quantity: 1,
    deliveryLocation: '',
    notificationsEnabled: false,
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<{
    type: 'success' | 'error' | null;
    message: string;
  }>({ type: null, message: '' });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touchedFields, setTouchedFields] = useState<Set<string>>(new Set());

  // Track form view
  useEffect(() => {
    feedbackService.trackEvent('lunch_order', 'order_form_viewed', {});
  }, []);

  // Validate field on blur (inline validation)
  const validateField = (fieldName: string, value: any): string | null => {
    const validationResult = lunchOrderService.validateLunchOrder({
      ...formData,
      [fieldName]: value,
    });

    const fieldError = validationResult.errors.find(
      (error) => error.field === fieldName
    );
    return fieldError ? fieldError.message : null;
  };

  // Handle field change
  const handleFieldChange = (
    fieldName: string,
    value: string | number | boolean
  ) => {
    setFormData((prev) => ({
      ...prev,
      [fieldName]: value,
    }));

    // Clear error when user starts typing
    if (errors[fieldName]) {
      setErrors((prev) => {
        const newErrors = { ...prev };
        delete newErrors[fieldName];
        return newErrors;
      });
    }
  };

  // Handle field blur (trigger inline validation)
  const handleFieldBlur = (fieldName: string) => {
    setTouchedFields((prev) => new Set(prev).add(fieldName));

    const error = validateField(fieldName, formData[fieldName as keyof LunchOrderSubmitRequest]);
    if (error) {
      setErrors((prev) => ({
        ...prev,
        [fieldName]: error,
      }));

      // Track validation error
      feedbackService.trackEvent('lunch_order', 'validation_error', {
        field: fieldName,
        error,
      });
    }
  };

  // Validate entire form
  const validateForm = (): boolean => {
    const validationResult = lunchOrderService.validateLunchOrder(formData);

    if (!validationResult.isValid) {
      const errorMap: Record<string, string> = {};
      validationResult.errors.forEach((error) => {
        errorMap[error.field] = error.message;
      });
      setErrors(errorMap);

      // Mark all fields as touched
      setTouchedFields(
        new Set([
          'name',
          'email',
          'menuSelection',
          'quantity',
          'specialInstructions',
          'deliveryLocation',
        ])
      );

      return false;
    }

    setErrors({});
    return true;
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Track submission attempt
    feedbackService.trackEvent('lunch_order', 'order_submit_attempted', {});

    if (!validateForm()) {
      setSubmitStatus({
        type: 'error',
        message: 'Please correct the errors before submitting',
      });

      // Track validation failure at submission
      feedbackService.trackEvent('lunch_order', 'order_submit_validation_failed', {
        errorCount: Object.keys(errors).length,
        errorFields: Object.keys(errors),
      });

      return;
    }

    setIsSubmitting(true);
    setSubmitStatus({ type: null, message: '' });

    try {
      const response = await lunchOrderService.submitLunchOrder(formData);

      if (response.success) {
        setSubmitStatus({
          type: 'success',
          message: response.message || 'Order submitted successfully!',
        });

        // Track successful submission
        feedbackService.trackEvent('lunch_order', 'order_submit_success', {
          orderId: response.orderId,
        });

        // Reset form
        setFormData({
          name: '',
          email: '',
          menuSelection: '',
          specialInstructions: '',
          quantity: 1,
          deliveryLocation: '',
          notificationsEnabled: false,
        });
        setErrors({});
        setTouchedFields(new Set());

        // Call success callback
        if (onSuccess && response.orderId) {
          onSuccess(response.orderId);
        }
      } else {
        setSubmitStatus({
          type: 'error',
          message: response.message || 'Failed to submit order',
        });

        // Set validation errors if provided
        if (response.validationErrors) {
          setErrors(response.validationErrors);
        }

        // Track submission error
        feedbackService.trackEvent('lunch_order', 'order_submit_error', {
          error: response.error,
        });
      }
    } catch (error) {
      setSubmitStatus({
        type: 'error',
        message: 'An unexpected error occurred. Please try again.',
      });

      // Track error
      feedbackService.trackError(error as Error, {
        context: 'lunch_order_submission',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle cancel
  const handleCancel = () => {
    // Track abandonment
    const hasFilledFields = Object.values(formData).some(
      (value) => value !== '' && value !== 1 && value !== false
    );

    if (hasFilledFields) {
      feedbackService.trackEvent('lunch_order', 'order_form_abandoned', {
        filledFields: Object.keys(formData).filter(
          (key) => formData[key as keyof LunchOrderSubmitRequest] !== ''
        ),
      });
    }

    if (onCancel) {
      onCancel();
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.formCard}>
        <h2 style={styles.title}>Lunch Order Form</h2>
        <p style={styles.subtitle}>
          Please fill out all required fields to place your lunch order
        </p>

        <form onSubmit={handleSubmit} style={styles.form}>
          {/* Name Field */}
          <div style={styles.formGroup}>
            <label htmlFor="name" style={styles.label}>
              Name <span style={styles.required}>*</span>
            </label>
            <input
              id="name"
              type="text"
              value={formData.name}
              onChange={(e) => handleFieldChange('name', e.target.value)}
              onBlur={() => handleFieldBlur('name')}
              style={{
                ...styles.input,
                ...(errors.name && touchedFields.has('name')
                  ? styles.inputError
                  : {}),
              }}
              placeholder="Enter your full name"
              aria-invalid={!!errors.name && touchedFields.has('name')}
              aria-describedby={errors.name ? 'name-error' : undefined}
            />
            {errors.name && touchedFields.has('name') && (
              <span id="name-error" style={styles.errorMessage} role="alert">
                {errors.name}
              </span>
            )}
          </div>

          {/* Email Field */}
          <div style={styles.formGroup}>
            <label htmlFor="email" style={styles.label}>
              Email (optional)
            </label>
            <input
              id="email"
              type="email"
              value={formData.email}
              onChange={(e) => handleFieldChange('email', e.target.value)}
              onBlur={() => handleFieldBlur('email')}
              style={{
                ...styles.input,
                ...(errors.email && touchedFields.has('email')
                  ? styles.inputError
                  : {}),
              }}
              placeholder="your.email@example.com"
              aria-invalid={!!errors.email && touchedFields.has('email')}
              aria-describedby={errors.email ? 'email-error' : undefined}
            />
            {errors.email && touchedFields.has('email') && (
              <span id="email-error" style={styles.errorMessage} role="alert">
                {errors.email}
              </span>
            )}
          </div>

          {/* Menu Selection Field */}
          <div style={styles.formGroup}>
            <label htmlFor="menuSelection" style={styles.label}>
              Menu Selection <span style={styles.required}>*</span>
            </label>
            <select
              id="menuSelection"
              value={formData.menuSelection}
              onChange={(e) => handleFieldChange('menuSelection', e.target.value)}
              onBlur={() => handleFieldBlur('menuSelection')}
              style={{
                ...styles.select,
                ...(errors.menuSelection && touchedFields.has('menuSelection')
                  ? styles.inputError
                  : {}),
              }}
              aria-invalid={
                !!errors.menuSelection && touchedFields.has('menuSelection')
              }
              aria-describedby={
                errors.menuSelection ? 'menuSelection-error' : undefined
              }
            >
              <option value="">-- Select a menu item --</option>
              <option value="Grilled Chicken Sandwich">
                Grilled Chicken Sandwich
              </option>
              <option value="Caesar Salad">Caesar Salad</option>
              <option value="Vegetarian Pizza">Vegetarian Pizza</option>
              <option value="Beef Burger">Beef Burger</option>
              <option value="Pasta Carbonara">Pasta Carbonara</option>
              <option value="Sushi Platter">Sushi Platter</option>
              <option value="BBQ Ribs">BBQ Ribs</option>
              <option value="Fish and Chips">Fish and Chips</option>
            </select>
            {errors.menuSelection && touchedFields.has('menuSelection') && (
              <span
                id="menuSelection-error"
                style={styles.errorMessage}
                role="alert"
              >
                {errors.menuSelection}
              </span>
            )}
          </div>

          {/* Quantity Field */}
          <div style={styles.formGroup}>
            <label htmlFor="quantity" style={styles.label}>
              Quantity <span style={styles.required}>*</span>
            </label>
            <input
              id="quantity"
              type="number"
              min="1"
              max="1000"
              value={formData.quantity}
              onChange={(e) =>
                handleFieldChange('quantity', parseInt(e.target.value, 10) || 1)
              }
              onBlur={() => handleFieldBlur('quantity')}
              style={{
                ...styles.input,
                ...(errors.quantity && touchedFields.has('quantity')
                  ? styles.inputError
                  : {}),
              }}
              aria-invalid={!!errors.quantity && touchedFields.has('quantity')}
              aria-describedby={errors.quantity ? 'quantity-error' : undefined}
            />
            {errors.quantity && touchedFields.has('quantity') && (
              <span id="quantity-error" style={styles.errorMessage} role="alert">
                {errors.quantity}
              </span>
            )}
          </div>

          {/* Special Instructions Field */}
          <div style={styles.formGroup}>
            <label htmlFor="specialInstructions" style={styles.label}>
              Special Instructions (optional)
            </label>
            <textarea
              id="specialInstructions"
              value={formData.specialInstructions}
              onChange={(e) =>
                handleFieldChange('specialInstructions', e.target.value)
              }
              onBlur={() => handleFieldBlur('specialInstructions')}
              style={{
                ...styles.textarea,
                ...(errors.specialInstructions &&
                touchedFields.has('specialInstructions')
                  ? styles.inputError
                  : {}),
              }}
              placeholder="Any dietary restrictions or special requests?"
              rows={3}
              maxLength={1000}
              aria-invalid={
                !!errors.specialInstructions &&
                touchedFields.has('specialInstructions')
              }
              aria-describedby={
                errors.specialInstructions
                  ? 'specialInstructions-error'
                  : undefined
              }
            />
            {errors.specialInstructions &&
              touchedFields.has('specialInstructions') && (
                <span
                  id="specialInstructions-error"
                  style={styles.errorMessage}
                  role="alert"
                >
                  {errors.specialInstructions}
                </span>
              )}
          </div>

          {/* Delivery Location Field */}
          <div style={styles.formGroup}>
            <label htmlFor="deliveryLocation" style={styles.label}>
              Delivery Location (optional)
            </label>
            <input
              id="deliveryLocation"
              type="text"
              value={formData.deliveryLocation}
              onChange={(e) =>
                handleFieldChange('deliveryLocation', e.target.value)
              }
              onBlur={() => handleFieldBlur('deliveryLocation')}
              style={{
                ...styles.input,
                ...(errors.deliveryLocation &&
                touchedFields.has('deliveryLocation')
                  ? styles.inputError
                  : {}),
              }}
              placeholder="Building, floor, or room number"
              aria-invalid={
                !!errors.deliveryLocation &&
                touchedFields.has('deliveryLocation')
              }
              aria-describedby={
                errors.deliveryLocation ? 'deliveryLocation-error' : undefined
              }
            />
            {errors.deliveryLocation &&
              touchedFields.has('deliveryLocation') && (
                <span
                  id="deliveryLocation-error"
                  style={styles.errorMessage}
                  role="alert"
                >
                  {errors.deliveryLocation}
                </span>
              )}
          </div>

          {/* Notifications Checkbox */}
          <div style={styles.checkboxGroup}>
            <label style={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={formData.notificationsEnabled}
                onChange={(e) =>
                  handleFieldChange('notificationsEnabled', e.target.checked)
                }
                style={styles.checkbox}
              />
              Send me notifications about my order
            </label>
          </div>

          {/* Submit Status Message */}
          {submitStatus.type && (
            <div
              style={{
                ...styles.statusMessage,
                ...(submitStatus.type === 'success'
                  ? styles.successMessage
                  : styles.errorMessageBox),
              }}
              role="alert"
            >
              {submitStatus.message}
            </div>
          )}

          {/* Action Buttons */}
          <div style={styles.buttonGroup}>
            <button
              type="submit"
              disabled={isSubmitting || Object.keys(errors).length > 0}
              style={{
                ...styles.submitButton,
                ...(isSubmitting || Object.keys(errors).length > 0
                  ? styles.submitButtonDisabled
                  : {}),
              }}
            >
              {isSubmitting ? 'Submitting...' : 'Place Order'}
            </button>

            {onCancel && (
              <button
                type="button"
                onClick={handleCancel}
                disabled={isSubmitting}
                style={styles.cancelButton}
              >
                Cancel
              </button>
            )}
          </div>

          {/* Required Fields Notice */}
          <p style={styles.requiredNotice}>
            <span style={styles.required}>*</span> Required fields
          </p>
        </form>
      </div>
    </div>
  );
};

// Inline styles for self-contained component
const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    padding: '20px',
    backgroundColor: '#f5f5f5',
    minHeight: '100vh',
  },
  formCard: {
    backgroundColor: 'white',
    borderRadius: '8px',
    padding: '30px',
    maxWidth: '600px',
    width: '100%',
    boxShadow: '0 2px 10px rgba(0, 0, 0, 0.1)',
  },
  title: {
    fontSize: '28px',
    fontWeight: 'bold',
    marginBottom: '10px',
    color: '#333',
    textAlign: 'center',
  },
  subtitle: {
    fontSize: '14px',
    color: '#666',
    marginBottom: '30px',
    textAlign: 'center',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  label: {
    fontSize: '14px',
    fontWeight: '500',
    color: '#333',
  },
  required: {
    color: '#e53e3e',
    fontWeight: 'bold',
  },
  input: {
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.2s',
  },
  select: {
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.2s',
    backgroundColor: 'white',
  },
  textarea: {
    padding: '10px 12px',
    fontSize: '14px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.2s',
    resize: 'vertical',
    fontFamily: 'inherit',
  },
  inputError: {
    borderColor: '#e53e3e',
  },
  errorMessage: {
    fontSize: '12px',
    color: '#e53e3e',
    marginTop: '4px',
  },
  checkboxGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '14px',
    color: '#333',
    cursor: 'pointer',
  },
  checkbox: {
    width: '18px',
    height: '18px',
    cursor: 'pointer',
  },
  statusMessage: {
    padding: '12px',
    borderRadius: '6px',
    fontSize: '14px',
    fontWeight: '500',
  },
  successMessage: {
    backgroundColor: '#d1fae5',
    color: '#065f46',
    border: '1px solid #6ee7b7',
  },
  errorMessageBox: {
    backgroundColor: '#fee2e2',
    color: '#991b1b',
    border: '1px solid #fca5a5',
  },
  buttonGroup: {
    display: 'flex',
    gap: '12px',
    marginTop: '10px',
  },
  submitButton: {
    flex: 1,
    padding: '12px 24px',
    fontSize: '16px',
    fontWeight: '600',
    color: 'white',
    backgroundColor: '#3b82f6',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  },
  submitButtonDisabled: {
    backgroundColor: '#9ca3af',
    cursor: 'not-allowed',
  },
  cancelButton: {
    flex: 1,
    padding: '12px 24px',
    fontSize: '16px',
    fontWeight: '600',
    color: '#333',
    backgroundColor: '#e5e7eb',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  },
  requiredNotice: {
    fontSize: '12px',
    color: '#666',
    textAlign: 'center',
    marginTop: '10px',
  },
};
