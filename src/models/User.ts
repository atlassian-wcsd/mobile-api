/**
 * Interface representing a user in the MFIRST system
 */
export interface User {
  /**
   * Unique identifier for the user
   */
  id: string;

  /**
   * User's email address (used for login and communication)
   */
  email: string;

  /**
   * User's hashed password
   */
  passwordHash: string;

  /**
   * User's full name
   */
  fullName: string;

  /**
   * User's phone number
   */
  phoneNumber?: string;

  /**
   * Flag indicating if email has been verified
   */
  isEmailVerified: boolean;

  /**
   * Timestamp of email verification
   */
  emailVerifiedAt?: Date;

  /**
   * Timestamp when the user account was created
   */
  createdAt: Date;

  /**
   * Timestamp of last account update
   */
  updatedAt: Date;

  /**
   * Timestamp of last login
   */
  lastLoginAt?: Date;

  /**
   * Number of failed login attempts
   */
  failedLoginAttempts: number;

  /**
   * Account status (active, suspended, locked)
   */
  status: UserStatus;

  /**
   * Password reset token (if requested)
   */
  passwordResetToken?: string;

  /**
   * Expiration time for password reset token
   */
  passwordResetExpires?: Date;

  /**
   * Security preferences
   */
  securitySettings: {
    /**
     * Two-factor authentication enabled
     */
    twoFactorEnabled: boolean;

    /**
     * Preferred 2FA method (email, sms, authenticator)
     */
    twoFactorMethod?: TwoFactorMethod;
  };

  /**
   * User preferences and settings
   */
  preferences: {
    /**
     * Preferred language
     */
    language: string;

    /**
     * Notification preferences
     */
    notifications: {
      email: boolean;
      sms: boolean;
      push: boolean;
    };
  };

  /**
   * Audit log of account activities
   */
  auditLog: AuditLogEntry[];
}

/**
 * Possible user account statuses
 */
export enum UserStatus {
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  LOCKED = 'locked',
  PENDING_VERIFICATION = 'pending_verification'
}

/**
 * Available two-factor authentication methods
 */
export enum TwoFactorMethod {
  EMAIL = 'email',
  SMS = 'sms',
  AUTHENTICATOR = 'authenticator'
}

/**
 * Interface for audit log entries
 */
export interface AuditLogEntry {
  /**
   * Timestamp of the activity
   */
  timestamp: Date;

  /**
   * Type of activity
   */
  activity: string;

  /**
   * IP address where the activity originated
   */
  ipAddress: string;

  /**
   * Device/browser information
   */
  userAgent: string;

  /**
   * Additional details about the activity
   */
  details?: Record<string, unknown>;
}

/**
 * Interface for user registration data
 */
export interface UserRegistrationData {
  email: string;
  password: string;
  fullName: string;
  phoneNumber?: string;
  captchaToken: string;
}

/**
 * Interface for password reset request
 */
export interface PasswordResetRequest {
  email: string;
  token: string;
  newPassword: string;
}