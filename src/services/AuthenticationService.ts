import { User, LoginRequest, LoginResponse, PasswordResetRequest, AuthError } from '../models/User';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

/**
 * Service class for handling user authentication
 */
export class AuthenticationService {
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
  private readonly TOKEN_EXPIRY = '1h';
  private readonly PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  private users: Map<string, User> = new Map();
  private rateLimiter: Map<string, { attempts: number; timestamp: number }> = new Map();

  /**
   * Attempt to log in a user
   * @param loginRequest Login credentials and MFA code if required
   * @returns LoginResponse with token if successful
   */
  public async login(loginRequest: LoginRequest): Promise<LoginResponse> {
    try {
      // Check rate limiting
      if (this.isRateLimited(loginRequest.email)) {
        return { success: false, error: AuthError.RATE_LIMIT_EXCEEDED };
      }

      const user = this.findUserByEmail(loginRequest.email);
      if (!user) {
        this.recordFailedAttempt(loginRequest.email);
        return { success: false, error: AuthError.INVALID_CREDENTIALS };
      }

      // Check if account is locked
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        return { success: false, error: AuthError.ACCOUNT_LOCKED };
      }

      // Verify password
      if (!this.verifyPassword(loginRequest.password, user.passwordHash, user.passwordSalt)) {
        this.recordFailedAttempt(loginRequest.email);
        return { success: false, error: AuthError.INVALID_CREDENTIALS };
      }

      // Check MFA if enabled
      if (user.mfaEnabled) {
        if (!loginRequest.mfaCode) {
          return { success: false, requiresMfa: true };
        }
        if (!this.verifyMfaCode(loginRequest.mfaCode, user.mfaSecret!)) {
          return { success: false, error: AuthError.INVALID_MFA };
        }
      }

      // Success - generate token and update user
      const token = this.generateToken(user);
      this.updateUserLoginSuccess(user);

      return {
        success: true,
        token,
        user: this.sanitizeUser(user)
      };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'An unexpected error occurred' };
    }
  }

  /**
   * Initialize password reset process
   * @param email User's email address
   * @returns true if reset token was sent, false if user not found
   */
  public async initiatePasswordReset(email: string): Promise<boolean> {
    const user = this.findUserByEmail(email);
    if (!user) return false;

    const resetToken = this.generateResetToken();
    // TODO: Store reset token with expiry
    // TODO: Send reset email to user

    return true;
  }

  /**
   * Reset user's password using reset token
   * @param resetRequest Password reset request data
   * @returns true if password was reset successfully
   */
  public async resetPassword(resetRequest: PasswordResetRequest): Promise<boolean> {
    // Validate password strength
    if (!this.isPasswordStrong(resetRequest.newPassword)) {
      throw new Error('Password does not meet security requirements');
    }

    // TODO: Verify reset token and update password
    return true;
  }

  /**
   * Enable MFA for a user
   * @param userId User ID
   * @returns MFA secret and QR code URL
   */
  public async enableMfa(userId: string): Promise<{ secret: string; qrCode: string }> {
    const user = this.users.get(userId);
    if (!user) throw new Error('User not found');

    const secret = this.generateMfaSecret();
    user.mfaEnabled = true;
    user.mfaSecret = secret;
    this.users.set(userId, user);

    // TODO: Generate QR code URL
    return {
      secret,
      qrCode: 'TODO: Generate QR code URL'
    };
  }

  /**
   * Verify if a password meets security requirements
   * @param password Password to verify
   * @returns true if password is strong enough
   */
  private isPasswordStrong(password: string): boolean {
    return this.PASSWORD_REGEX.test(password);
  }

  /**
   * Generate a secure hash of a password
   * @param password Plain text password
   * @param salt Salt for hashing
   * @returns Hashed password
   */
  private hashPassword(password: string, salt: string): string {
    return crypto
      .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
      .toString('hex');
  }

  /**
   * Verify a password against its hash
   * @param password Plain text password
   * @param hash Stored password hash
   * @param salt Stored salt
   * @returns true if password is correct
   */
  private verifyPassword(password: string, hash: string, salt: string): boolean {
    const testHash = this.hashPassword(password, salt);
    return testHash === hash;
  }

  /**
   * Generate a JWT token for a user
   * @param user User object
   * @returns JWT token
   */
  private generateToken(user: User): string {
    const payload = {
      userId: user.id,
      email: user.email
    };
    
    // TODO: Use proper secret key from environment
    return jwt.sign(payload, 'temporary-secret-key', { expiresIn: this.TOKEN_EXPIRY });
  }

  /**
   * Check if login attempts are rate limited
   * @param email User's email
   * @returns true if rate limited
   */
  private isRateLimited(email: string): boolean {
    const limit = this.rateLimiter.get(email);
    if (!limit) return false;

    const now = Date.now();
    if (now - limit.timestamp > this.LOCKOUT_DURATION) {
      this.rateLimiter.delete(email);
      return false;
    }

    return limit.attempts >= this.MAX_LOGIN_ATTEMPTS;
  }

  /**
   * Record a failed login attempt
   * @param email User's email
   */
  private recordFailedAttempt(email: string): void {
    const limit = this.rateLimiter.get(email) || { attempts: 0, timestamp: Date.now() };
    limit.attempts++;
    this.rateLimiter.set(email, limit);
  }

  /**
   * Update user record after successful login
   * @param user User object
   */
  private updateUserLoginSuccess(user: User): void {
    user.failedLoginAttempts = 0;
    user.lastLoginAt = new Date();
    user.lockedUntil = undefined;
    this.users.set(user.id, user);
  }

  /**
   * Find a user by email address
   * @param email User's email
   * @returns User object if found
   */
  private findUserByEmail(email: string): User | undefined {
    return Array.from(this.users.values()).find(u => u.email === email);
  }

  /**
   * Remove sensitive data from user object
   * @param user User object
   * @returns Sanitized user object
   */
  private sanitizeUser(user: User): Omit<User, 'passwordHash' | 'passwordSalt' | 'mfaSecret'> {
    const { passwordHash, passwordSalt, mfaSecret, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  /**
   * Generate a random MFA secret
   * @returns MFA secret string
   */
  private generateMfaSecret(): string {
    return crypto.randomBytes(20).toString('hex');
  }

  /**
   * Generate a password reset token
   * @returns Reset token
   */
  private generateResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Verify an MFA code
   * @param code MFA code from user
   * @param secret User's MFA secret
   * @returns true if code is valid
   */
  private verifyMfaCode(code: string, secret: string): boolean {
    // TODO: Implement proper TOTP verification
    return code === '123456'; // Temporary implementation
  }
}