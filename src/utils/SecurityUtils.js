const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 bytes
const IV_LENGTH = 16; // For AES-256-GCM
const SALT_ROUNDS = 10;

class SecurityUtils {
  /**
   * Encrypt sensitive data
   * @param {string} text - Text to encrypt
   * @returns {string} - Encrypted text
   */
  static encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return IV:AuthTag:EncryptedData
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt encrypted data
   * @param {string} encryptedData - Data to decrypt
   * @returns {string} - Decrypted text
   */
  static decrypt(encryptedData) {
    const [ivHex, authTagHex, encryptedText] = encryptedData.split(':');
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
    
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} - Validation result with details
   */
  static validatePasswordStrength(password) {
    const result = {
      isValid: false,
      errors: []
    };

    // Minimum length check
    if (password.length < 8) {
      result.errors.push('Password must be at least 8 characters long');
    }

    // Uppercase letter check
    if (!/[A-Z]/.test(password)) {
      result.errors.push('Password must contain at least one uppercase letter');
    }

    // Lowercase letter check
    if (!/[a-z]/.test(password)) {
      result.errors.push('Password must contain at least one lowercase letter');
    }

    // Number check
    if (!/\d/.test(password)) {
      result.errors.push('Password must contain at least one number');
    }

    // Special character check
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      result.errors.push('Password must contain at least one special character');
    }

    result.isValid = result.errors.length === 0;
    return result;
  }

  /**
   * Hash password using bcrypt
   * @param {string} password - Password to hash
   * @returns {Promise<string>} - Hashed password
   */
  static async hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
  }

  /**
   * Compare password with hash
   * @param {string} password - Password to compare
   * @param {string} hash - Hash to compare against
   * @returns {Promise<boolean>} - Whether password matches hash
   */
  static async comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  /**
   * Generate secure random token
   * @param {number} length - Length of token
   * @returns {string} - Generated token
   */
  static generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Create rate limiter middleware
   * @param {Object} options - Rate limiting options
   * @returns {Function} - Rate limiter middleware
   */
  static createRateLimiter(options = {}) {
    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 100, // Limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later',
      standardHeaders: true,
      legacyHeaders: false,
      ...options
    });
  }

  /**
   * Create login attempt rate limiter
   * @returns {Function} - Login rate limiter middleware
   */
  static createLoginRateLimiter() {
    return this.createRateLimiter({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 attempts
      message: 'Too many login attempts, please try again later'
    });
  }

  /**
   * Log security event
   * @param {string} event - Event description
   * @param {Object} metadata - Additional metadata
   */
  static logSecurityEvent(event, metadata = {}) {
    const logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({ filename: 'security.log' })
      ]
    });

    logger.info(event, {
      timestamp: new Date().toISOString(),
      ...metadata
    });
  }

  /**
   * Sanitize user input to prevent XSS
   * @param {string} input - Input to sanitize
   * @returns {string} - Sanitized input
   */
  static sanitizeInput(input) {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Generate session ID
   * @returns {string} - Secure session ID
   */
  static generateSessionId() {
    return crypto.randomBytes(32).toString('base64');
  }

  /**
   * Validate session token
   * @param {string} token - Session token to validate
   * @returns {boolean} - Whether token is valid
   */
  static validateSessionToken(token) {
    // Basic validation - should be expanded based on your session format
    return token && token.length >= 32 && /^[A-Za-z0-9+/=]+$/.test(token);
  }
}

module.exports = SecurityUtils;