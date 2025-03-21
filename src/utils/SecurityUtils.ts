import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { RateLimiter } from 'rate-limiter-flexible';

// Password strength requirements
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_REQUIRES_UPPERCASE = true;
const PASSWORD_REQUIRES_LOWERCASE = true;
const PASSWORD_REQUIRES_NUMBER = true;
const PASSWORD_REQUIRES_SPECIAL = true;

// Rate limiting configuration
const rateLimiter = new RateLimiter({
  points: 5, // Number of attempts
  duration: 60 * 15, // Per 15 minutes
});

/**
 * Validates password strength based on defined requirements
 * @param password Password to validate
 * @returns Object containing validation result and any error messages
 */
export const validatePasswordStrength = (password: string): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];

  if (password.length < PASSWORD_MIN_LENGTH) {
    errors.push(`Password must be at least ${PASSWORD_MIN_LENGTH} characters long`);
  }

  if (PASSWORD_REQUIRES_UPPERCASE && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (PASSWORD_REQUIRES_LOWERCASE && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (PASSWORD_REQUIRES_NUMBER && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (PASSWORD_REQUIRES_SPECIAL && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

/**
 * Hashes a password using bcrypt
 * @param password Plain text password
 * @returns Hashed password
 */
export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
};

/**
 * Verifies a password against its hash
 * @param password Plain text password
 * @param hash Hashed password
 * @returns Boolean indicating if password matches
 */
export const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

/**
 * Generates a secure random token for password reset or 2FA
 * @param length Length of the token
 * @returns Secure random token
 */
export const generateSecureToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Encrypts sensitive data
 * @param data Data to encrypt
 * @param key Encryption key
 * @returns Encrypted data
 */
export const encryptData = (data: string, key: string): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return JSON.stringify({
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag: authTag.toString('hex'),
  });
};

/**
 * Decrypts encrypted data
 * @param encryptedData Encrypted data object
 * @param key Decryption key
 * @returns Decrypted data
 */
export const decryptData = (encryptedData: string, key: string): string => {
  const { iv, encryptedData: data, authTag } = JSON.parse(encryptedData);
  
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(key),
    Buffer.from(iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

/**
 * Checks if login attempts are within rate limits
 * @param userId User identifier (e.g., username or IP)
 * @returns Promise resolving to boolean indicating if attempt is allowed
 */
export const checkLoginRateLimit = async (userId: string): Promise<boolean> => {
  try {
    await rateLimiter.consume(userId);
    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Generates a session token
 * @param userId User identifier
 * @returns Session token
 */
export const generateSessionToken = (userId: string): string => {
  const timestamp = Date.now();
  const randomString = crypto.randomBytes(32).toString('hex');
  return `${userId}-${timestamp}-${randomString}`;
};

/**
 * Validates a session token
 * @param token Session token
 * @param maxAge Maximum age of session in milliseconds
 * @returns Object containing validation result and user ID
 */
export const validateSessionToken = (
  token: string,
  maxAge: number
): { isValid: boolean; userId?: string } => {
  try {
    const [userId, timestamp] = token.split('-');
    const tokenAge = Date.now() - parseInt(timestamp);
    
    if (tokenAge > maxAge) {
      return { isValid: false };
    }
    
    return { isValid: true, userId };
  } catch {
    return { isValid: false };
  }
};