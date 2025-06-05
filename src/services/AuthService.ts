import { AuthKey, AuthRequest, AuthResponse } from '../models/Auth';

/**
 * Service class for handling key-based authentication
 */
export class AuthService {
  private keys: Map<string, AuthKey> = new Map();

  /**
   * Authenticate a user using their key
   * @param request The authentication request containing key ID and value
   * @returns Authentication response with success status and token/error
   */
  public async authenticate(request: AuthRequest): Promise<AuthResponse> {
    const key = this.keys.get(request.keyId);

    if (!key) {
      return {
        success: false,
        error: 'Invalid key ID'
      };
    }

    if (key.status !== 'active') {
      return {
        success: false,
        error: `Key is ${key.status}`
      };
    }

    if (key.expiresAt && key.expiresAt < new Date()) {
      key.status = 'expired';
      this.keys.set(key.keyId, key);
      return {
        success: false,
        error: 'Key has expired'
      };
    }

    if (key.keyValue !== request.keyValue) {
      return {
        success: false,
        error: 'Invalid key value'
      };
    }

    // Generate a session token
    const token = this.generateToken();

    return {
      success: true,
      token,
      userId: key.keyId // Using keyId as userId for now
    };
  }

  /**
   * Create a new authentication key
   * @param expiresAt Optional expiration date for the key
   * @returns The created authentication key
   */
  public createKey(expiresAt?: Date): AuthKey {
    const key: AuthKey = {
      keyId: this.generateKeyId(),
      keyValue: this.generateKeyValue(),
      createdAt: new Date(),
      expiresAt,
      status: 'active'
    };

    this.keys.set(key.keyId, key);
    return key;
  }

  /**
   * Revoke an authentication key
   * @param keyId The ID of the key to revoke
   * @returns true if the key was revoked, false if not found
   */
  public revokeKey(keyId: string): boolean {
    const key = this.keys.get(keyId);
    if (!key) return false;

    key.status = 'revoked';
    this.keys.set(keyId, key);
    return true;
  }

  /**
   * Generate a unique key ID
   * @returns A unique string ID for the key
   */
  private generateKeyId(): string {
    return 'key_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Generate a secure key value
   * @returns A secure random string for the key value
   */
  private generateKeyValue(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = 32;
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
      result += chars.charAt(randomValues[i] % chars.length);
    }
    return result;
  }

  /**
   * Generate a session token
   * @returns A secure random string for the session token
   */
  private generateToken(): string {
    return 'sess_' + Date.now() + '_' + this.generateKeyValue();
  }
}