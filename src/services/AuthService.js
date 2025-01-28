const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const User = require('../models/User');
const logger = require('../utils/logger');
const { encrypt, decrypt } = require('../utils/encryption');
const { sendResetPasswordEmail, sendMFACode } = require('../utils/emailService');

class AuthService {
  /**
   * Authenticate user and initiate MFA if enabled
   * @param {string} email
   * @param {string} password
   * @returns {Promise<Object>}
   */
  async authenticateUser(email, password) {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`Authentication attempt for non-existent user: ${email}`);
      throw new Error('Invalid credentials');
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      logger.warn(`Failed password verification for user: ${email}`);
      throw new Error('Invalid credentials');
    }

    if (user.mfaEnabled) {
      const mfaToken = speakeasy.generateSecret();
      await sendMFACode(user.email, mfaToken.base32);
      
      // Store encrypted MFA token
      user.tempMFAToken = encrypt(mfaToken.base32);
      await user.save();
      
      return {
        requiresMFA: true,
        message: 'MFA code sent to email'
      };
    }

    const token = this._generateToken(user);
    logger.info(`Successful authentication for user: ${email}`);

    return {
      token,
      user: this._sanitizeUser(user)
    };
  }

  /**
   * Verify MFA code and complete authentication
   * @param {string} email
   * @param {string} mfaCode
   * @returns {Promise<Object>}
   */
  async verifyMFACode(email, mfaCode) {
    const user = await User.findOne({ email });
    if (!user || !user.tempMFAToken) {
      throw new Error('Invalid or expired MFA session');
    }

    const decryptedToken = decrypt(user.tempMFAToken);
    const isValidMFA = speakeasy.totp.verify({
      secret: decryptedToken,
      encoding: 'base32',
      token: mfaCode
    });

    if (!isValidMFA) {
      logger.warn(`Failed MFA verification for user: ${email}`);
      throw new Error('Invalid MFA code');
    }

    // Clear temporary MFA token
    user.tempMFAToken = null;
    await user.save();

    const token = this._generateToken(user);
    logger.info(`Successful MFA verification for user: ${email}`);

    return {
      token,
      user: this._sanitizeUser(user)
    };
  }

  /**
   * Initiate password reset process
   * @param {string} email
   * @returns {Promise<void>}
   */
  async initiatePasswordReset(email) {
    const user = await User.findOne({ email });
    if (!user) {
      // Return silently to prevent email enumeration
      return;
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = encrypt(resetToken);
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    await sendResetPasswordEmail(email, resetToken);
    logger.info(`Password reset initiated for user: ${email}`);
  }

  /**
   * Complete password reset with new password
   * @param {string} token
   * @param {string} newPassword
   * @returns {Promise<void>}
   */
  async resetPassword(token, newPassword) {
    const user = await User.findOne({
      resetPasswordToken: encrypt(token),
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    if (!this.validatePasswordStrength(newPassword)) {
      throw new Error('Password does not meet security requirements');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    logger.info(`Password reset completed for user: ${user.email}`);
  }

  /**
   * Validate password strength
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
   * Generate JWT token for authenticated user
   * @param {User} user
   * @returns {string}
   * @private
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

  /**
   * Remove sensitive data from user object
   * @param {User} user
   * @returns {Object}
   * @private
   */
  _sanitizeUser(user) {
    return {
      id: user.id,
      email: user.email,
      name: user.name
    };
  }

  /**
   * Validate user session
   * @param {string} token
   * @returns {Promise<Object>}
   */
  async validateSession(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (!user) {
        throw new Error('User not found');
      }

      return this._sanitizeUser(user);
    } catch (error) {
      throw new Error('Invalid session');
    }
  }
}

module.exports = new AuthService();