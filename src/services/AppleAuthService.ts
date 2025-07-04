import { AppleUser, AppleAuthRequest, AppleAuthResponse, AppleUserBuilder } from '../models/AppleUser';

export class AppleAuthService {
  private readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor() {
    this.baseUrl = process.env.REACT_APP_API_BASE_URL || 'https://api.yourapp.com';
    this.apiKey = process.env.REACT_APP_API_KEY;
  }

  /**
   * Verify Apple ID token with backend and get user information
   */
  async verifyAppleToken(identityToken: string, authorizationCode?: string, userInfo?: any): Promise<AppleUser> {
    try {
      const request: AppleAuthRequest = {
        identityToken,
        authorizationCode: authorizationCode || '',
        user: userInfo
      };

      const response = await this.makeRequest('/auth/apple/verify', {
        method: 'POST',
        body: JSON.stringify(request)
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new Error(data.error || 'Apple authentication failed');
      }

      return data.user;
    } catch (error) {
      console.error('Apple token verification failed:', error);
      throw new Error(error instanceof Error ? error.message : 'Token verification failed');
    }
  }

  /**
   * Refresh Apple authentication token
   */
  async refreshToken(refreshToken: string): Promise<AppleUser> {
    try {
      const response = await this.makeRequest('/auth/apple/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken })
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new Error(data.error || 'Token refresh failed');
      }

      return data.user;
    } catch (error) {
      console.error('Apple token refresh failed:', error);
      throw new Error(error instanceof Error ? error.message : 'Token refresh failed');
    }
  }

  /**
   * Sign out user and revoke Apple tokens
   */
  async signOut(authToken: string): Promise<void> {
    try {
      const response = await this.makeRequest('/auth/apple/signout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (!response.ok) {
        throw new Error('Sign out failed');
      }
    } catch (error) {
      console.error('Apple sign out failed:', error);
      throw new Error(error instanceof Error ? error.message : 'Sign out failed');
    }
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(authToken: string): Promise<AppleUser> {
    try {
      const response = await this.makeRequest('/auth/apple/profile', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new Error(data.error || 'Failed to get user profile');
      }

      return data.user;
    } catch (error) {
      console.error('Get user profile failed:', error);
      throw new Error(error instanceof Error ? error.message : 'Failed to get user profile');
    }
  }

  /**
   * Validate Apple ID token locally (basic validation)
   */
  validateTokenFormat(token: string): boolean {
    try {
      // Basic JWT format validation
      const parts = token.split('.');
      if (parts.length !== 3) {
        return false;
      }

      // Decode header and payload (without verification)
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));

      // Basic checks
      return (
        header.alg === 'RS256' &&
        header.kid &&
        payload.iss === 'https://appleid.apple.com' &&
        payload.aud &&
        payload.exp &&
        payload.iat &&
        payload.sub
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Parse Apple ID token payload (without verification)
   */
  parseTokenPayload(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid token format');
      }

      return JSON.parse(atob(parts[1]));
    } catch (error) {
      throw new Error('Failed to parse token payload');
    }
  }

  /**
   * Make HTTP request with common headers and error handling
   */
  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultHeaders: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    if (this.apiKey) {
      defaultHeaders['X-API-Key'] = this.apiKey;
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers
      }
    };

    const response = await fetch(url, config);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    return response;
  }
}

/**
 * Utility functions for Apple authentication
 */
export class AppleAuthUtils {
  /**
   * Generate a secure random state parameter
   */
  static generateState(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generate a secure random nonce
   */
  static generateNonce(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Validate email format
   */
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Check if token is expired
   */
  static isTokenExpired(expiresAt: Date): boolean {
    return new Date() >= expiresAt;
  }
}