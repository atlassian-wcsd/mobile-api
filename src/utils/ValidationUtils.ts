/**
 * ValidationUtils.ts
 * Utility functions for validating user registration data
 */

// Regular expressions for validation
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const PHONE_REGEX = /^\+?[\d\s-]{10,}$/;

/**
 * Interface for validation error messages
 */
export interface ValidationErrors {
  email?: string;
  password?: string;
  confirmPassword?: string;
  phoneNumber?: string;
  firstName?: string;
  lastName?: string;
  captcha?: string;
}

/**
 * Interface for registration form data
 */
export interface RegistrationFormData {
  email: string;
  password: string;
  confirmPassword: string;
  phoneNumber?: string;
  firstName: string;
  lastName: string;
  captchaToken?: string;
}

/**
 * Validates email format
 * @param email - Email address to validate
 * @returns boolean indicating if email is valid
 */
export const isValidEmail = (email: string): boolean => {
  return EMAIL_REGEX.test(email);
};

/**
 * Validates password strength
 * Must contain:
 * - At least 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 * @param password - Password to validate
 * @returns boolean indicating if password meets requirements
 */
export const isValidPassword = (password: string): boolean => {
  return PASSWORD_REGEX.test(password);
};

/**
 * Validates phone number format
 * @param phoneNumber - Phone number to validate
 * @returns boolean indicating if phone number is valid
 */
export const isValidPhoneNumber = (phoneNumber: string): boolean => {
  return PHONE_REGEX.test(phoneNumber);
};

/**
 * Validates registration form data
 * @param data - Registration form data to validate
 * @returns Object containing validation errors if any
 */
export const validateRegistrationForm = (data: RegistrationFormData): ValidationErrors => {
  const errors: ValidationErrors = {};

  // Validate email
  if (!data.email) {
    errors.email = 'Email is required';
  } else if (!isValidEmail(data.email)) {
    errors.email = 'Please enter a valid email address';
  }

  // Validate password
  if (!data.password) {
    errors.password = 'Password is required';
  } else if (!isValidPassword(data.password)) {
    errors.password = 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character';
  }

  // Validate password confirmation
  if (!data.confirmPassword) {
    errors.confirmPassword = 'Please confirm your password';
  } else if (data.password !== data.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match';
  }

  // Validate phone number if provided
  if (data.phoneNumber && !isValidPhoneNumber(data.phoneNumber)) {
    errors.phoneNumber = 'Please enter a valid phone number';
  }

  // Validate first name
  if (!data.firstName.trim()) {
    errors.firstName = 'First name is required';
  }

  // Validate last name
  if (!data.lastName.trim()) {
    errors.lastName = 'Last name is required';
  }

  // Validate CAPTCHA
  if (!data.captchaToken) {
    errors.captcha = 'Please complete the CAPTCHA verification';
  }

  return errors;
};

/**
 * Checks if the registration form has any validation errors
 * @param errors - Validation errors object
 * @returns boolean indicating if form has errors
 */
export const hasValidationErrors = (errors: ValidationErrors): boolean => {
  return Object.keys(errors).length > 0;
};