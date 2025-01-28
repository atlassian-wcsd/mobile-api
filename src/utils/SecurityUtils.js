/**
 * SecurityUtils.js
 * Utility functions for handling security-related operations
 */

import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Constants for security configurations
const SALT_ROUNDS = 10;
const PASSWORD_MIN_LENGTH = 8;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds
const TOKEN_EXPIRY = '24h';

class SecurityUtils {
    /**
     * Validates password strength
     * @param {string} password - Password to validate
     * @returns {Object} Validation result with status and message
     */
    static validatePasswordStrength(password) {
        const requirements = {
            minLength: password.length >= PASSWORD_MIN_LENGTH,
            hasUpperCase: /[A-Z]/.test(password),
            hasLowerCase: /[a-z]/.test(password),
            hasNumbers: /\d/.test(password),
            hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };

        const missingRequirements = Object.entries(requirements)
            .filter(([, meets]) => !meets)
            .map(([req]) => req);

        return {
            isValid: missingRequirements.length === 0,
            message: missingRequirements.length === 0
                ? 'Password meets all requirements'
                : `Password must include: ${missingRequirements.join(', ')}`
        };
    }

    /**
     * Hashes a password using bcrypt
     * @param {string} password - Plain text password
     * @returns {Promise<string>} Hashed password
     */
    static async hashPassword(password) {
        return bcrypt.hash(password, SALT_ROUNDS);
    }

    /**
     * Verifies a password against its hash
     * @param {string} password - Plain text password to verify
     * @param {string} hash - Stored hash to compare against
     * @returns {Promise<boolean>} Whether the password matches
     */
    static async verifyPassword(password, hash) {
        return bcrypt.compare(password, hash);
    }

    /**
     * Generates a secure token for MFA
     * @returns {string} MFA token
     */
    static generateMFAToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Creates a JWT token for user session
     * @param {Object} userData - User data to encode in token
     * @returns {string} JWT token
     */
    static createSessionToken(userData) {
        return jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    }

    /**
     * Verifies a JWT token
     * @param {string} token - Token to verify
     * @returns {Object|null} Decoded token data or null if invalid
     */
    static verifySessionToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return null;
        }
    }

    /**
     * Encrypts sensitive data
     * @param {string} data - Data to encrypt
     * @returns {string} Encrypted data
     */
    static encryptData(data) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
            iv
        );
        
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    /**
     * Decrypts encrypted data
     * @param {Object} encryptedData - Object containing encrypted data, IV, and auth tag
     * @returns {string} Decrypted data
     */
    static decryptData({ encrypted, iv, authTag }) {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
            Buffer.from(iv, 'hex')
        );
        
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    /**
     * Implements rate limiting check
     * @param {string} userId - User ID to check
     * @param {Map} loginAttempts - Map to track login attempts
     * @returns {Object} Rate limiting status
     */
    static checkRateLimit(userId, loginAttempts) {
        const userAttempts = loginAttempts.get(userId) || { 
            count: 0, 
            lastAttempt: Date.now() 
        };

        if (userAttempts.count >= MAX_LOGIN_ATTEMPTS) {
            const timeSinceLastAttempt = Date.now() - userAttempts.lastAttempt;
            if (timeSinceLastAttempt < LOCKOUT_DURATION) {
                return {
                    isLocked: true,
                    remainingTime: LOCKOUT_DURATION - timeSinceLastAttempt
                };
            }
            // Reset if lockout duration has passed
            userAttempts.count = 0;
        }

        return {
            isLocked: false,
            attempts: userAttempts.count
        };
    }

    /**
     * Generates a secure password reset token
     * @returns {string} Reset token
     */
    static generatePasswordResetToken() {
        return crypto.randomBytes(32).toString('base64');
    }

    /**
     * Logs security events
     * @param {string} event - Event to log
     * @param {Object} details - Event details
     */
    static logSecurityEvent(event, details) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            event,
            details,
        };
        // TODO: Implement actual logging mechanism (e.g., to secure logging service)
        console.log('Security Event:', logEntry);
    }
}

export default SecurityUtils;