// Authentication related types and interfaces

// User credentials interface
export interface UserCredentials {
    email: string;
    password: string;
    mfaCode?: string;
}

// Password requirements interface
export interface PasswordRequirements {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
}

// Authentication response interface
export interface AuthResponse {
    success: boolean;
    token?: string;
    refreshToken?: string;
    mfaRequired?: boolean;
    error?: string;
    remainingAttempts?: number;
}

// Session information interface
export interface SessionInfo {
    userId: string;
    token: string;
    expiresAt: Date;
    lastActivity: Date;
    deviceInfo: DeviceInfo;
}

// Device information interface
export interface DeviceInfo {
    deviceId: string;
    deviceType: string;
    platform: string;
    browser?: string;
    ipAddress: string;
}

// Login attempt interface for rate limiting and security monitoring
export interface LoginAttempt {
    timestamp: Date;
    ipAddress: string;
    success: boolean;
    userId?: string;
    deviceInfo: DeviceInfo;
    errorType?: string;
}

// Password reset request interface
export interface PasswordResetRequest {
    email: string;
    token: string;
    expiresAt: Date;
    used: boolean;
}

// Security audit log interface
export interface SecurityAuditLog {
    timestamp: Date;
    eventType: SecurityEventType;
    userId?: string;
    ipAddress: string;
    details: string;
    severity: SecuritySeverity;
}

// Security event types enum
export enum SecurityEventType {
    LOGIN_SUCCESS = 'LOGIN_SUCCESS',
    LOGIN_FAILURE = 'LOGIN_FAILURE',
    PASSWORD_RESET = 'PASSWORD_RESET',
    MFA_ENABLED = 'MFA_ENABLED',
    MFA_DISABLED = 'MFA_DISABLED',
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
    SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY'
}

// Security severity levels enum
export enum SecuritySeverity {
    LOW = 'LOW',
    MEDIUM = 'MEDIUM',
    HIGH = 'HIGH',
    CRITICAL = 'CRITICAL'
}

// Rate limiting configuration interface
export interface RateLimitConfig {
    maxAttempts: number;
    timeWindow: number; // in milliseconds
    blockDuration: number; // in milliseconds
}

// Multi-factor authentication configuration interface
export interface MFAConfig {
    enabled: boolean;
    type: MFAType;
    secret?: string;
    backupCodes?: string[];
}

// MFA types enum
export enum MFAType {
    AUTHENTICATOR = 'AUTHENTICATOR',
    SMS = 'SMS',
    EMAIL = 'EMAIL'
}

// Default password requirements
export const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
};

// Default rate limit configuration
export const DEFAULT_RATE_LIMIT_CONFIG: RateLimitConfig = {
    maxAttempts: 5,
    timeWindow: 15 * 60 * 1000, // 15 minutes
    blockDuration: 60 * 60 * 1000 // 1 hour
};