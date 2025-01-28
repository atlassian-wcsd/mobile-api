const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/emailService');
const logger = require('../utils/logger');

// Rate limiting configuration
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again after 15 minutes'
});

class AuthController {
  // User registration
  async register(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, phoneNumber } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Password strength validation
      if (!this.validatePasswordStrength(password)) {
        return res.status(400).json({
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
        });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create new user
      const user = new User({
        email,
        password: hashedPassword,
        phoneNumber,
        mfaEnabled: false,
        verificationToken: this.generateVerificationToken()
      });

      await user.save();

      // Send verification email
      await sendVerificationEmail(email, user.verificationToken);

      logger.info(`New user registered: ${email}`);
      res.status(201).json({ message: 'Registration successful. Please verify your email.' });
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      res.status(500).json({ message: 'Server error during registration' });
    }
  }

  // User login
  async login(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, mfaCode } = req.body;

      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        logger.warn(`Failed login attempt for user: ${email}`);
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if email is verified
      if (!user.isVerified) {
        return res.status(401).json({ message: 'Please verify your email first' });
      }

      // Check MFA if enabled
      if (user.mfaEnabled) {
        if (!mfaCode) {
          return res.status(400).json({ message: 'MFA code required' });
        }
        const isValidMFA = this.verifyMFACode(user, mfaCode);
        if (!isValidMFA) {
          return res.status(401).json({ message: 'Invalid MFA code' });
        }
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // Update last login timestamp
      user.lastLogin = new Date();
      await user.save();

      logger.info(`Successful login for user: ${email}`);
      res.json({
        token,
        user: {
          id: user._id,
          email: user.email,
          mfaEnabled: user.mfaEnabled
        }
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      res.status(500).json({ message: 'Server error during login' });
    }
  }

  // Password reset request
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const resetToken = this.generateResetToken();
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      await sendPasswordResetEmail(email, resetToken);

      logger.info(`Password reset requested for user: ${email}`);
      res.json({ message: 'Password reset email sent' });
    } catch (error) {
      logger.error(`Password reset request error: ${error.message}`);
      res.status(500).json({ message: 'Server error during password reset request' });
    }
  }

  // Reset password
  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      if (!this.validatePasswordStrength(newPassword)) {
        return res.status(400).json({
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
        });
      }

      // Hash new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      logger.info(`Password reset successful for user: ${user.email}`);
      res.json({ message: 'Password reset successful' });
    } catch (error) {
      logger.error(`Password reset error: ${error.message}`);
      res.status(500).json({ message: 'Server error during password reset' });
    }
  }

  // Enable/Disable MFA
  async toggleMFA(req, res) {
    try {
      const userId = req.user.id; // From auth middleware
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      user.mfaEnabled = !user.mfaEnabled;
      await user.save();

      logger.info(`MFA ${user.mfaEnabled ? 'enabled' : 'disabled'} for user: ${user.email}`);
      res.json({ message: `MFA ${user.mfaEnabled ? 'enabled' : 'disabled'}` });
    } catch (error) {
      logger.error(`MFA toggle error: ${error.message}`);
      res.status(500).json({ message: 'Server error while toggling MFA' });
    }
  }

  // Verify email
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;
      const user = await User.findOne({ verificationToken: token });

      if (!user) {
        return res.status(400).json({ message: 'Invalid verification token' });
      }

      user.isVerified = true;
      user.verificationToken = undefined;
      await user.save();

      logger.info(`Email verified for user: ${user.email}`);
      res.json({ message: 'Email verification successful' });
    } catch (error) {
      logger.error(`Email verification error: ${error.message}`);
      res.status(500).json({ message: 'Server error during email verification' });
    }
  }

  // Helper methods
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

  generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  verifyMFACode(user, code) {
    // Implement MFA code verification logic here
    // This could use TOTP, SMS, or other MFA methods
    return true; // Placeholder
  }
}

module.exports = new AuthController();