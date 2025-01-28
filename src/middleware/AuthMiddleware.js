const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');
const AuthService = require('../services/AuthService');

class AuthMiddleware {
  /**
   * Rate limiter for login attempts
   * Limits to 5 attempts per 15 minutes
   */
  static loginRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
      res.status(429).json({
        message: 'Too many login attempts, please try again after 15 minutes'
      });
    }
  });

  /**
   * Rate limiter for password reset attempts
   * Limits to 3 attempts per hour
   */
  static passwordResetRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 attempts per window
    message: 'Too many password reset attempts, please try again after an hour',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn(`Password reset rate limit exceeded for IP: ${req.ip}`);
      res.status(429).json({
        message: 'Too many password reset attempts, please try again after an hour'
      });
    }
  });

  /**
   * Middleware to verify JWT token and validate session
   */
  static async authenticateToken(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        return res.status(401).json({ message: 'Authentication token required' });
      }

      try {
        // Validate session using AuthService
        const user = await AuthService.validateSession(token);
        req.user = user;
        next();
      } catch (error) {
        logger.warn(`Invalid session token: ${error.message}`);
        return res.status(401).json({ message: 'Invalid or expired session' });
      }
    } catch (error) {
      logger.error('Authentication middleware error:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }

  /**
   * Middleware to validate password strength
   */
  static validatePassword(req, res, next) {
    const { password } = req.body;

    if (!AuthService.validatePasswordStrength(password)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
      });
    }

    next();
  }

  /**
   * Middleware to sanitize user input
   */
  static sanitizeInput(req, res, next) {
    // Sanitize request body
    if (req.body) {
      Object.keys(req.body).forEach(key => {
        if (typeof req.body[key] === 'string') {
          req.body[key] = req.body[key].trim();
        }
      });
    }

    next();
  }

  /**
   * Middleware to log authentication attempts
   */
  static logAuthAttempt(req, res, next) {
    const { email } = req.body;
    logger.info(`Authentication attempt for user: ${email}`);
    next();
  }

  /**
   * Middleware to check if MFA is required
   */
  static async checkMFARequired(req, res, next) {
    try {
      const { email } = req.body;
      const user = await AuthService.validateSession(req.headers.authorization.split(' ')[1]);
      
      if (user.mfaEnabled && !req.body.mfaCode) {
        return res.status(403).json({
          message: 'MFA code required',
          requiresMFA: true
        });
      }

      next();
    } catch (error) {
      logger.error('MFA check error:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
}

module.exports = AuthMiddleware;