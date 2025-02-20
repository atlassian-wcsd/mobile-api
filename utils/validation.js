// Input validation utilities for mobile user registration

/**
 * Validates email format
 * @param {string} email - Email address to validate
 * @returns {boolean} True if email format is valid
 */
export const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

/**
 * Validates password strength
 * @param {string} password - Password to validate
 * @returns {object} Validation result with isValid flag and message
 */
export const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
        return {
            isValid: false,
            message: 'Password must be at least 8 characters long'
        };
    }

    if (!hasUpperCase || !hasLowerCase) {
        return {
            isValid: false,
            message: 'Password must contain both uppercase and lowercase letters'
        };
    }

    if (!hasNumbers) {
        return {
            isValid: false,
            message: 'Password must contain at least one number'
        };
    }

    if (!hasSpecialChar) {
        return {
            isValid: false,
            message: 'Password must contain at least one special character'
        };
    }

    return {
        isValid: true,
        message: 'Password meets all requirements'
    };
};

/**
 * Validates phone number format (Czech Republic)
 * @param {string} phoneNumber - Phone number to validate
 * @returns {boolean} True if phone number format is valid
 */
export const isValidPhoneNumber = (phoneNumber) => {
    // Czech phone number format: +420 XXX XXX XXX or XXX XXX XXX
    const phoneRegex = /^(\+420\s?)?\d{3}\s?\d{3}\s?\d{3}$/;
    return phoneRegex.test(phoneNumber.replace(/\s/g, ''));
};

/**
 * Validates required fields are not empty
 * @param {object} fields - Object containing field names and values
 * @returns {object} Validation result with isValid flag and errors object
 */
export const validateRequiredFields = (fields) => {
    const errors = {};
    let isValid = true;

    Object.entries(fields).forEach(([field, value]) => {
        if (!value || value.trim() === '') {
            errors[field] = 'This field is required';
            isValid = false;
        }
    });

    return {
        isValid,
        errors
    };
};

/**
 * Validates complete registration form
 * @param {object} formData - Registration form data
 * @returns {object} Validation result with isValid flag and errors object
 */
export const validateRegistrationForm = (formData) => {
    const { name, email, password, phoneNumber } = formData;
    const errors = {};
    
    // Check required fields
    const requiredCheck = validateRequiredFields({ name, email, password, phoneNumber });
    if (!requiredCheck.isValid) {
        return {
            isValid: false,
            errors: requiredCheck.errors
        };
    }

    // Validate email
    if (!isValidEmail(email)) {
        errors.email = 'Please enter a valid email address';
    }

    // Validate password
    const passwordCheck = validatePassword(password);
    if (!passwordCheck.isValid) {
        errors.password = passwordCheck.message;
    }

    // Validate phone number
    if (!isValidPhoneNumber(phoneNumber)) {
        errors.phoneNumber = 'Please enter a valid Czech phone number';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};