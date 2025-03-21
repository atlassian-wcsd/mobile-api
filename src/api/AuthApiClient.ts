import axios, { AxiosInstance } from 'axios';
import { LoginCredentials, LoginResponse, PasswordResetRequest, MFAVerification } from '../types/auth';

export class AuthApiClient {
  private api: AxiosInstance;
  private static readonly MAX_LOGIN_ATTEMPTS = 5;
  private static readonly LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds

  constructor(baseURL: string) {
    this.api = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor for rate limiting
    this.api.interceptors.request.use(
      (config) => {
        // Add rate limiting headers
        config.headers['X-Rate-Limit'] = 'true';
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );
  }

  /**
   * Authenticate user with credentials
   * @param credentials User login credentials
   * @returns Login response with token and MFA status
   */
  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    try {
      const response = await this.api.post('/auth/login', credentials);
      this.logLoginActivity(credentials.username, true);
      return response.data;
    } catch (error: any) {
      this.logLoginActivity(credentials.username, false);
      this.handleLoginError(error);
      throw error;
    }
  }

  /**
   * Verify MFA code for two-factor authentication
   * @param verification MFA verification details
   * @returns Updated login response
   */
  async verifyMFA(verification: MFAVerification): Promise<LoginResponse> {
    try {
      const response = await this.api.post('/auth/mfa/verify', verification);
      return response.data;
    } catch (error: any) {
      throw new Error('MFA verification failed: ' + error.message);
    }
  }

  /**
   * Request password reset for user
   * @param request Password reset request details
   */
  async requestPasswordReset(request: PasswordResetRequest): Promise<void> {
    try {
      await this.api.post('/auth/password/reset-request', request);
    } catch (error: any) {
      throw new Error('Password reset request failed: ' + error.message);
    }
  }

  /**
   * Reset password with token
   * @param token Reset token
   * @param newPassword New password
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    try {
      await this.api.post('/auth/password/reset', {
        token,
        newPassword,
      });
    } catch (error: any) {
      throw new Error('Password reset failed: ' + error.message);
    }
  }

  /**
   * Validate password strength
   * @param password Password to validate
   * @returns Boolean indicating if password meets requirements
   */
  validatePassword(password: string): boolean {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumbers &&
      hasSpecialChar
    );
  }

  /**
   * Log out user and invalidate session
   */
  async logout(): Promise<void> {
    try {
      await this.api.post('/auth/logout');
    } catch (error: any) {
      throw new Error('Logout failed: ' + error.message);
    }
  }

  private handleLoginError(error: any): void {
    if (error.response) {
      switch (error.response.status) {
        case 429:
          throw new Error('Too many login attempts. Please try again later.');
        case 401:
          throw new Error('Invalid credentials. Please check your username and password.');
        case 403:
          throw new Error('Account locked. Please contact support.');
        default:
          throw new Error('Login failed: ' + error.message);
      }
    }
    throw error;
  }

  private logLoginActivity(username: string, success: boolean): void {
    // Log login attempt for security monitoring
    console.log(`Login attempt for user ${username}: ${success ? 'success' : 'failure'}`);
    // In a production environment, this would send logs to a security monitoring service
  }
}