import { AppleUser, AppleAuthRequest, AppleAuthResponse } from '../models/AppleUser';

// Custom error classes for better error handling
export class AppleAuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = 'AppleAuthError';
  }
}

export class AppleConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AppleConfigError';
  }
}

// Configuration interface
interface AppleAuthConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retryAttempts?: number;
}

export class AppleAuthService {
  private readonly config: AppleAuthConfig;
  private readonly abortController: AbortController;

  constructor(config?: Partial<AppleAuthConfig>) {
    // Validate required configuration
    const baseUrl = config?.baseUrl || process.env.REACT_APP_API_BASE_URL;
    if (!baseUrl) {
      throw new AppleConfigError('API base URL is required');
    }

    this.config = {
      baseUrl,
      apiKey: config?.apiKey || process.env.REACT_APP_API_KEY,
      timeout: config?.timeout || 30000, // 30 seconds
      retryAttempts: config?.retryAttempts || 3
    };

    this.abortController = new AbortController();
  }

  /**
   * Verify Apple ID token with backend and get user information
   */
  async verifyAppleToken(
    identityToken: string, 
    authorizationCode?: string, 
    userInfo?: any
  ): Promise<AppleUser> {
    this.validateToken(identityToken);

    const request: AppleAuthRequest = {
      identityToken,
      authorizationCode: authorizationCode || '',
      user: userInfo
    };

    try {
      const response = await this.makeRequestWithRetry('/auth/apple/verify', {
        method: 'POST',
        body: JSON.stringify(request)
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new AppleAuthError(
          data.error || 'Apple authentication failed',
          'AUTH_FAILED',
          response.status
        );
      }

      return data.user;
    } catch (error) {
      if (error instanceof AppleAuthError) {
        throw error;
      }
      throw new AppleAuthError(
        error instanceof Error ? error.message : 'Token verification failed',
        'VERIFICATION_ERROR'
      );
    }
  }

  /**
   * Refresh Apple authentication token with retry logic
   */
  async refreshToken(refreshToken: string): Promise<AppleUser> {
    if (!refreshToken?.trim()) {
      throw new AppleAuthError('Refresh token is required', 'INVALID_TOKEN');
    }

    try {
      const response = await this.makeRequestWithRetry('/auth/apple/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken })
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new AppleAuthError(
          data.error || 'Token refresh failed',
          'REFRESH_FAILED',
          response.status
        );
      }

      return data.user;
    } catch (error) {
      if (error instanceof AppleAuthError) {
        throw error;
      }
      throw new AppleAuthError(
        error instanceof Error ? error.message : 'Token refresh failed',
        'REFRESH_ERROR'
      );
    }
  }

  /**
   * Sign out user and revoke Apple tokens
   */
  async signOut(authToken: string): Promise<void> {
    if (!authToken?.trim()) {
      throw new AppleAuthError('Auth token is required', 'INVALID_TOKEN');
    }

    try {
      const response = await this.makeRequestWithRetry('/auth/apple/signout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (!response.ok) {
        throw new AppleAuthError(
          'Sign out failed',
          'SIGNOUT_FAILED',
          response.status
        );
      }
    } catch (error) {
      if (error instanceof AppleAuthError) {
        throw error;
      }
      throw new AppleAuthError(
        error instanceof Error ? error.message : 'Sign out failed',
        'SIGNOUT_ERROR'
      );
    }
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(authToken: string): Promise<AppleUser> {
    if (!authToken?.trim()) {
      throw new AppleAuthError('Auth token is required', 'INVALID_TOKEN');
    }

    try {
      const response = await this.makeRequestWithRetry('/auth/apple/profile', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      const data: AppleAuthResponse = await response.json();

      if (!data.success || !data.user) {
        throw new AppleAuthError(
          data.error || 'Failed to get user profile',
          'PROFILE_ERROR',
          response.status
        );
      }

      return data.user;
    } catch (error) {
      if (error instanceof AppleAuthError) {
        throw error;
      }
      throw new AppleAuthError(
        error instanceof Error ? error.message : 'Failed to get user profile',
        'PROFILE_ERROR'
      );
    }
  }

  /**
   * Cancel all pending requests
   */
  cancelRequests(): void {
    this.abortController.abort();
  }

  /**
   * Validate Apple ID token format
   */
  private validateToken(token: string): void {
    if (!token?.trim()) {
      throw new AppleAuthError('Identity token is required', 'INVALID_TOKEN');
    }

    // Basic JWT format validation
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new AppleAuthError('Invalid token format', 'INVALID_TOKEN_FORMAT');
    }

    try {
      // Validate header and payload can be decoded
      JSON.parse(atob(parts[0]));
      JSON.parse(atob(parts[1]));
    } catch {
      throw new AppleAuthError('Invalid token encoding', 'INVALID_TOKEN_ENCODING');
    }
  }

  /**
   * Make HTTP request with retry logic
   */
  private async makeRequestWithRetry(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<Response> {
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= this.config.retryAttempts!; attempt++) {
      try {
        const response = await this.makeRequest(endpoint, options);
        
        // Don't retry on client errors (4xx)
        if (response.status >= 400 && response.status < 500) {
          return response;
        }
        
        // Retry on server errors (5xx) or network errors
        if (response.ok || attempt === this.config.retryAttempts) {
          return response;
        }
        
        // Wait before retry with exponential backoff
        await this.delay(Math.pow(2, attempt - 1) * 1000);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        if (attempt === this.config.retryAttempts) {
          break;
        }
        
        // Wait before retry
        await this.delay(Math.pow(2, attempt - 1) * 1000);
      }
    }

    throw lastError || new Error('All retry attempts failed');
  }

  /**
   * Make HTTP request with timeout and proper headers
   */
  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.config.baseUrl}${endpoint}`;
    
    const defaultHeaders: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    if (this.config.apiKey) {
      defaultHeaders['X-API-Key'] = this.config.apiKey;
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers
      },
      signal: this.abortController.signal
    };

    // Add timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout')), this.config.timeout);
    });

    const response = await Promise.race([
      fetch(url, config),
      timeoutPromise
    ]);

    if (!response.ok && response.status >= 500) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response;
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Singleton instance for global use
let globalAppleAuthService: AppleAuthService | null = null;

export const getAppleAuthService = (config?: Partial<AppleAuthConfig>): AppleAuthService => {
  if (!globalAppleAuthService) {
    globalAppleAuthService = new AppleAuthService(config);
  }
  return globalAppleAuthService;
};

// Utility functions
export class AppleAuthUtils {
  /**
   * Generate a secure random state parameter
   */
  static generateState(): string {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    // Fallback for older browsers
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15) + 
           Date.now().toString(36);
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

  /**
   * Parse JWT payload without verification
   */
  static parseJWTPayload(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      return JSON.parse(atob(parts[1]));
    } catch {
      throw new Error('Failed to parse JWT payload');
    }
  }
}