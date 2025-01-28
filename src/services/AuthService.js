import axios from 'axios';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

class AuthService {
    constructor() {
        this.baseURL = process.env.API_BASE_URL;
        this.loginAttempts = new Map(); // Track login attempts for rate limiting
        this.sessionDuration = 3600; // 1 hour in seconds
    }

    /**
     * Validates password strength
     * @param {string} password
     * @returns {boolean}
     */
    validatePasswordStrength(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        return password.length >= minLength &&
            hasUpperCase &&
            hasLowerCase &&
            hasNumbers &&
            hasSpecialChar;
    }

    /**
     * Check rate limiting for login attempts
     * @param {string} userId
     * @returns {boolean}
     */
    checkRateLimit(userId) {
        const maxAttempts = 5;
        const resetTime = 15 * 60 * 1000; // 15 minutes
        
        if (!this.loginAttempts.has(userId)) {
            this.loginAttempts.set(userId, {
                attempts: 1,
                timestamp: Date.now()
            });
            return true;
        }

        const userAttempts = this.loginAttempts.get(userId);
        if (Date.now() - userAttempts.timestamp > resetTime) {
            this.loginAttempts.set(userId, {
                attempts: 1,
                timestamp: Date.now()
            });
            return true;
        }

        if (userAttempts.attempts >= maxAttempts) {
            return false;
        }

        userAttempts.attempts++;
        return true;
    }

    /**
     * Authenticate user and handle login
     * @param {string} email
     * @param {string} password
     * @returns {Promise}
     */
    async login(email, password) {
        try {
            if (!this.checkRateLimit(email)) {
                throw new Error('Too many login attempts. Please try again later.');
            }

            const response = await axios.post(`${this.baseURL}/auth/login`, {
                email,
                password
            });

            if (response.data.requiresMFA) {
                return {
                    status: 'MFA_REQUIRED',
                    mfaToken: response.data.mfaToken
                };
            }

            this.startSession(response.data.token);
            this.logLoginActivity(email, true);
            
            return {
                status: 'SUCCESS',
                token: response.data.token,
                user: response.data.user
            };
        } catch (error) {
            this.logLoginActivity(email, false, error.message);
            throw new Error(error.response?.data?.message || 'Login failed');
        }
    }

    /**
     * Verify MFA token
     * @param {string} mfaToken
     * @param {string} verificationCode
     * @returns {Promise}
     */
    async verifyMFA(mfaToken, verificationCode) {
        try {
            const response = await axios.post(`${this.baseURL}/auth/verify-mfa`, {
                mfaToken,
                verificationCode
            });

            this.startSession(response.data.token);
            return {
                status: 'SUCCESS',
                token: response.data.token,
                user: response.data.user
            };
        } catch (error) {
            throw new Error(error.response?.data?.message || 'MFA verification failed');
        }
    }

    /**
     * Initiate password reset process
     * @param {string} email
     * @returns {Promise}
     */
    async requestPasswordReset(email) {
        try {
            await axios.post(`${this.baseURL}/auth/reset-password-request`, { email });
            return { status: 'SUCCESS', message: 'Password reset email sent' };
        } catch (error) {
            throw new Error(error.response?.data?.message || 'Password reset request failed');
        }
    }

    /**
     * Reset password with token
     * @param {string} token
     * @param {string} newPassword
     * @returns {Promise}
     */
    async resetPassword(token, newPassword) {
        if (!this.validatePasswordStrength(newPassword)) {
            throw new Error('Password does not meet security requirements');
        }

        try {
            await axios.post(`${this.baseURL}/auth/reset-password`, {
                token,
                newPassword
            });
            return { status: 'SUCCESS', message: 'Password successfully reset' };
        } catch (error) {
            throw new Error(error.response?.data?.message || 'Password reset failed');
        }
    }

    /**
     * Start user session
     * @param {string} token
     */
    startSession(token) {
        localStorage.setItem('authToken', token);
        localStorage.setItem('sessionStart', Date.now().toString());
    }

    /**
     * Check if session is valid
     * @returns {boolean}
     */
    isSessionValid() {
        const token = localStorage.getItem('authToken');
        const sessionStart = localStorage.getItem('sessionStart');

        if (!token || !sessionStart) {
            return false;
        }

        const sessionAge = (Date.now() - parseInt(sessionStart)) / 1000;
        return sessionAge < this.sessionDuration;
    }

    /**
     * End user session
     */
    logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('sessionStart');
    }

    /**
     * Log login activity for security monitoring
     * @param {string} email
     * @param {boolean} success
     * @param {string} errorMessage
     */
    async logLoginActivity(email, success, errorMessage = null) {
        try {
            await axios.post(`${this.baseURL}/auth/log-activity`, {
                email,
                activity: 'login',
                success,
                errorMessage,
                timestamp: new Date().toISOString(),
                ipAddress: window.clientInformation?.ip,
                userAgent: navigator.userAgent
            });
        } catch (error) {
            console.error('Failed to log login activity:', error);
        }
    }

    /**
     * Get current authentication token
     * @returns {string|null}
     */
    getAuthToken() {
        return localStorage.getItem('authToken');
    }
}

export default new AuthService();