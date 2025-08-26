import { AppleAuthService } from '../AppleAuthService';
import { AppleUser, AppleTokenPayload, AppleAuthRequest } from '../../models/AppleUser';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock environment variables
const originalEnv = process.env;
beforeEach(() => {
  jest.resetModules();
  process.env = {
    ...originalEnv,
    REACT_APP_API_BASE_URL: 'https://api.test.com',
  };
});

afterEach(() => {
  process.env = originalEnv;
  jest.clearAllMocks();
});

describe('AppleAuthService', () => {
  let service: AppleAuthService;

  beforeEach(() => {
    service = new AppleAuthService();
  });

  describe('verifyAppleToken', () => {
    it('successfully verifies Apple token and returns user', async () => {
      const mockUser: AppleUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        fullName: 'John Doe',
        isPrivateEmail: false,
        authToken: 'test-auth-token',
        refreshToken: 'test-refresh-token',
        expiresAt: new Date('2024-12-31'),
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-01'),
      };

      mockedAxios.post.mockResolvedValue({
        data: {
          success: true,
          user: mockUser,
        },
      });

      const result = await service.verifyAppleToken('mock-id-token');

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://api.test.com/auth/apple/verify',
        { identityToken: 'mock-id-token' },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      expect(result).toEqual(mockUser);
    });

    it('throws error when API returns error response', async () => {
      mockedAxios.post.mockResolvedValue({
        data: {
          success: false,
          error: 'Invalid token',
        },
      });

      await expect(service.verifyAppleToken('invalid-token')).rejects.toThrow('Invalid token');
    });

    it('throws error when API request fails', async () => {
      mockedAxios.post.mockRejectedValue(new Error('Network error'));

      await expect(service.verifyAppleToken('mock-token')).rejects.toThrow('Network error');
    });

    it('throws error when user data is missing from successful response', async () => {
      mockedAxios.post.mockResolvedValue({
        data: {
          success: true,
          // user is missing
        },
      });

      await expect(service.verifyAppleToken('mock-token')).rejects.toThrow('User data not found in response');
    });

    it('uses default API URL when environment variable is not set', async () => {
      process.env.REACT_APP_API_BASE_URL = '';

      const mockUser: AppleUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        fullName: 'John Doe',
        isPrivateEmail: false,
        authToken: 'test-auth-token',
        expiresAt: new Date('2024-12-31'),
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-01'),
      };

      mockedAxios.post.mockResolvedValue({
        data: {
          success: true,
          user: mockUser,
        },
      });

      await service.verifyAppleToken('mock-token');

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://api.yourapp.com/auth/apple/verify',
        { identityToken: 'mock-token' },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
    });
  });

  describe('refreshToken', () => {
    it('successfully refreshes token', async () => {
      const mockUser: AppleUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        authToken: 'new-auth-token',
        refreshToken: 'new-refresh-token',
        expiresAt: new Date('2024-12-31'),
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-01'),
      };

      mockedAxios.post.mockResolvedValue({
        data: {
          success: true,
          user: mockUser,
        },
      });

      const result = await service.refreshToken('old-refresh-token');

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://api.test.com/auth/apple/refresh',
        { refreshToken: 'old-refresh-token' },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      expect(result).toEqual(mockUser);
    });

    it('throws error when refresh fails', async () => {
      mockedAxios.post.mockResolvedValue({
        data: {
          success: false,
          error: 'Invalid refresh token',
        },
      });

      await expect(service.refreshToken('invalid-refresh-token')).rejects.toThrow('Invalid refresh token');
    });
  });

  describe('signOut', () => {
    it('successfully signs out user', async () => {
      mockedAxios.post.mockResolvedValue({
        data: {
          success: true,
          message: 'Signed out successfully',
        },
      });

      await service.signOut('test-auth-token');

      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://api.test.com/auth/apple/signout',
        {},
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test-auth-token',
          },
        }
      );
    });

    it('throws error when sign out fails', async () => {
      mockedAxios.post.mockResolvedValue({
        data: {
          success: false,
          error: 'Sign out failed',
        },
      });

      await expect(service.signOut('test-auth-token')).rejects.toThrow('Sign out failed');
    });
  });

  describe('getUserProfile', () => {
    it('successfully gets user profile', async () => {
      const mockUser: AppleUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        fullName: 'John Doe',
        isPrivateEmail: false,
        authToken: 'test-auth-token',
        expiresAt: new Date('2024-12-31'),
        createdAt: new Date('2024-01-01'),
        lastLoginAt: new Date('2024-01-01'),
      };

      mockedAxios.get.mockResolvedValue({
        data: {
          success: true,
          user: mockUser,
        },
      });

      const result = await service.getUserProfile('test-auth-token');

      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://api.test.com/auth/apple/profile',
        {
          headers: {
            'Authorization': 'Bearer test-auth-token',
          },
        }
      );

      expect(result).toEqual(mockUser);
    });

    it('throws error when profile request fails', async () => {
      mockedAxios.get.mockResolvedValue({
        data: {
          success: false,
          error: 'Unauthorized',
        },
      });

      await expect(service.getUserProfile('invalid-token')).rejects.toThrow('Unauthorized');
    });
  });

  describe('validateTokenPayload', () => {
    it('validates correct token payload', () => {
      const validPayload: AppleTokenPayload = {
        iss: 'https://appleid.apple.com',
        aud: 'com.yourapp.bundle',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-id-123',
        email: 'test@example.com',
        email_verified: true,
        is_private_email: false,
        auth_time: Math.floor(Date.now() / 1000),
      };

      expect(() => service.validateTokenPayload(validPayload)).not.toThrow();
    });

    it('throws error for expired token', () => {
      const expiredPayload: AppleTokenPayload = {
        iss: 'https://appleid.apple.com',
        aud: 'com.yourapp.bundle',
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
        sub: 'user-id-123',
        auth_time: Math.floor(Date.now() / 1000) - 7200,
      };

      expect(() => service.validateTokenPayload(expiredPayload)).toThrow('Token has expired');
    });

    it('throws error for invalid issuer', () => {
      const invalidIssuerPayload: AppleTokenPayload = {
        iss: 'https://invalid-issuer.com',
        aud: 'com.yourapp.bundle',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-id-123',
        auth_time: Math.floor(Date.now() / 1000),
      };

      expect(() => service.validateTokenPayload(invalidIssuerPayload)).toThrow('Invalid token issuer');
    });

    it('throws error for missing required fields', () => {
      const incompletePayload = {
        iss: 'https://appleid.apple.com',
        aud: 'com.yourapp.bundle',
        exp: Math.floor(Date.now() / 1000) + 3600,
        // missing iat, sub, auth_time
      } as AppleTokenPayload;

      expect(() => service.validateTokenPayload(incompletePayload)).toThrow('Missing required token fields');
    });
  });

  describe('parseAppleAuthRequest', () => {
    it('parses complete Apple auth request', () => {
      const authRequest: AppleAuthRequest = {
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
        user: {
          name: {
            firstName: 'John',
            lastName: 'Doe',
          },
          email: 'john@example.com',
        },
        state: 'random-state-string',
      };

      const result = service.parseAppleAuthRequest(authRequest);

      expect(result).toEqual({
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        state: 'random-state-string',
      });
    });

    it('parses minimal Apple auth request', () => {
      const authRequest: AppleAuthRequest = {
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
      };

      const result = service.parseAppleAuthRequest(authRequest);

      expect(result).toEqual({
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
        firstName: undefined,
        lastName: undefined,
        email: undefined,
        state: undefined,
      });
    });

    it('handles partial user data', () => {
      const authRequest: AppleAuthRequest = {
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
        user: {
          email: 'john@example.com',
          // name is missing
        },
      };

      const result = service.parseAppleAuthRequest(authRequest);

      expect(result).toEqual({
        identityToken: 'mock-identity-token',
        authorizationCode: 'mock-auth-code',
        firstName: undefined,
        lastName: undefined,
        email: 'john@example.com',
        state: undefined,
      });
    });
  });
});