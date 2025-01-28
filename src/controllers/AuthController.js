const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const speakeasy = require('speakeasy');
const { validationResult } = require('express-validator');
const logger = require('../utils/logger');
const User = require('../models/User');
const { sendResetPasswordEmail, sendMFACode } = require('../utils/emailService');
const { encrypt, decrypt } = require('../utils/encryption');

// Rate limiting configuration
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again after 15 minutes'
});

class AuthController {
  /**
   * User login with password and MFA
   * @param {Request} req
   * @param {Response} res
   */
  async login(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      // Find user and validate password
      const user = await User.findOne({ email });
      if (!user) {
        logger.warn(`Failed login attempt for non-existent user: ${email}`);
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        logger.warn(`Failed login attempt for user: ${email}`);
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Generate and validate MFA code
      if (user.mfaEnabled) {
        const mfaToken = speakeasy.generateSecret();
        await sendMFACode(user.email, mfaToken.base32);
        
        // Store MFA token temporarily
        user.tempMFAToken = encrypt(mfaToken.base32);
        await user.save();
        
        return res.status(200).json({ 
          message: 'MFA code sent to email',
          requiresMFA: true
        });
      }

      // Create session and JWT token
      const token = this._generateToken(user);
      
      // Log successful login
      logger.info(`Successful login for user: ${email}`);

      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  /**
   * Verify MFA code and complete login
   * @param {Request} req
   * @param {Response} res
   */
  async verifyMFA(req, res) {
    try {
      const { email, mfaCode } = req.body;
      
      const user = await User.findOne({ email });
      if (!user || !user.tempMFAToken) {
        return res.status(401).json({ message: 'Invalid or expired MFA session' });
      }

      const decryptedToken = decrypt(user.tempMFAToken);
      const isValidMFA = speakeasy.totp.verify({
        secret: decryptedToken,
        encoding: 'base32',
        token: mfaCode
      });

      if (!isValidMFA) {
        logger.warn(`Failed MFA attempt for user: ${email}`);
        return res.status(401).json({ message: 'Invalid MFA code' });
      }

      // Clear temporary MFA token
      user.tempMFAToken = null;
      await user.save();

      // Generate token and create session
      const token = this._generateToken(user);
      
      logger.info(`Successful MFA verification for user: ${email}`);

      res.status(200).json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error) {
      logger.error('MFA verification error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  /**
   * Initiate password reset process
   * @param {Request} req
   * @param {Response} res
   */
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;
      
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(200).json({ message: 'If the email exists, a reset link will be sent' });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = encrypt(resetToken);
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      await sendResetPasswordEmail(email, resetToken);
      logger.info(`Password reset requested for user: ${email}`);

      res.status(200).json({ message: 'If the email exists, a reset link will be sent' });
    } catch (error) {
      logger.error('Password reset request error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  /**
   * Complete password reset with new password
   * @param {Request} req
   * @param {Response} res
   */
  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      const user = await User.findOne({
        resetPasswordToken: encrypt(token),
        resetPasswordExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      // Validate password strength
      if (!this._validatePasswordStrength(newPassword)) {
        return res.status(400).json({ 
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character' 
        });
      }

      // Hash new password and update user
      user.password = await bcrypt.hash(newPassword, 10);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      logger.info(`Password reset completed for user: ${user.email}`);
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      logger.error('Password reset error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  /**
   * Validate password strength
   * @param {string} password
   * @returns {boolean}
   */
  _validatePasswordStrength(password) {
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
   * Generate JWT token
   * @param {User} user
   * @returns {string}
   */
  _generateToken(user) {
    return jwt.sign(
      { 
        id: user.id, 
        email: user.email 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  }
}

module.exports = new AuthController();