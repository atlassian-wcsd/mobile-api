/**
 * Interface for authentication key
 */
export interface AuthKey {
  /**
   * The unique key identifier
   */
  keyId: string;

  /**
   * The key value used for authentication
   */
  keyValue: string;

  /**
   * When the key was created
   */
  createdAt: Date;

  /**
   * When the key expires (if applicable)
   */
  expiresAt?: Date;

  /**
   * Status of the key (active, revoked, expired)
   */
  status: 'active' | 'revoked' | 'expired';
}

/**
 * Interface for authentication response
 */
export interface AuthResponse {
  /**
   * Whether authentication was successful
   */
  success: boolean;

  /**
   * Authentication token (if successful)
   */
  token?: string;

  /**
   * Error message (if unsuccessful)
   */
  error?: string;

  /**
   * User ID of the authenticated user
   */
  userId?: string;
}

/**
 * Interface for authentication request
 */
export interface AuthRequest {
  /**
   * The key ID for authentication
   */
  keyId: string;

  /**
   * The key value for authentication
   */
  keyValue: string;
}