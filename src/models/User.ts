/**
 * Interface representing a user in the system
 */
export interface User {
  /**
   * Unique identifier for the user
   */
  id: string;

  /**
   * User's email address (used for login)
   */
  email: string;

  /**
   * Hashed password
   */
  passwordHash: string;

  /**
   * Salt used for password hashing
   */
  passwordSalt: string;

  /**
   * Whether MFA is enabled for this user
   */
  mfaEnabled: boolean;

  /**
   * MFA secret key (if enabled)
   */
  mfaSecret?: string;

  /**
   * Number of failed login attempts
   */
  failedLoginAttempts: number;

  /**
   * Timestamp of account lockout (if any)
   */
  lockedUntil?: Date;

  /**
   * Last successful login timestamp
   */
  lastLoginAt?: Date;

  /**
   * Account creation timestamp
   */
  createdAt: Date;

  /**
   * Last update timestamp
   */
  updatedAt: Date;
}

/**
 * Interface for login request data
 */
export interface LoginRequest {
  email: string;
  password: string;
  mfaCode?: string;
}

/**
 * Interface for login response data
 */
export interface LoginResponse {
  success: boolean;
  token?: string;
  requiresMfa?: boolean;
  error?: string;
  user?: Omit<User, 'passwordHash' | 'passwordSalt' | 'mfaSecret'>;
}

/**
 * Interface for password reset request
 */
export interface PasswordResetRequest {
  email: string;
  resetToken: string;
  newPassword: string;
}

/**
 * Enum for authentication errors
 */
export enum AuthError {
  INVALID_CREDENTIALS = 'Invalid email or password',
  ACCOUNT_LOCKED = 'Account is temporarily locked due to too many failed attempts',
  MFA_REQUIRED = 'Multi-factor authentication code required',
  INVALID_MFA = 'Invalid multi-factor authentication code',
  RATE_LIMIT_EXCEEDED = 'Too many login attempts, please try again later',
  INVALID_RESET_TOKEN = 'Invalid or expired password reset token'
}