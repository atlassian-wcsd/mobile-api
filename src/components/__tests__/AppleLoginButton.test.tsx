import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { AppleLoginButton } from '../AppleLoginButton';
import { AppleAuthService } from '../../services/AppleAuthService';
import { AppleUser } from '../../models/AppleUser';

// Mock the AppleAuthService
jest.mock('../../services/AppleAuthService');

// Mock the global AppleID SDK
const mockAppleID = {
  auth: {
    init: jest.fn(),
    signIn: jest.fn(),
  },
};

Object.defineProperty(window, 'AppleID', {
  value: mockAppleID,
  writable: true,
});

// Mock environment variables
const originalEnv = process.env;
beforeEach(() => {
  jest.resetModules();
  process.env = {
    ...originalEnv,
    REACT_APP_APPLE_CLIENT_ID: 'test.client.id',
    REACT_APP_APPLE_REDIRECT_URI: 'https://test.example.com',
  };
});

afterEach(() => {
  process.env = originalEnv;
  jest.clearAllMocks();
});

describe('AppleLoginButton', () => {
  const mockOnSuccess = jest.fn();
  const mockOnError = jest.fn();
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

  beforeEach(() => {
    mockOnSuccess.mockClear();
    mockOnError.mockClear();
    mockAppleID.auth.init.mockClear();
    mockAppleID.auth.signIn.mockClear();
  });

  it('renders the login button with correct text', () => {
    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    expect(screen.getByText('Sign in with Apple')).toBeInTheDocument();
    expect(screen.getByRole('button')).toHaveClass('apple-login-button');
  });

  it('applies custom className when provided', () => {
    render(
      <AppleLoginButton
        onSuccess={mockOnSuccess}
        onError={mockOnError}
        className="custom-class"
      />
    );

    expect(screen.getByRole('button')).toHaveClass('apple-login-button custom-class');
  });

  it('disables button when disabled prop is true', () => {
    render(
      <AppleLoginButton
        onSuccess={mockOnSuccess}
        onError={mockOnError}
        disabled={true}
      />
    );

    const button = screen.getByRole('button');
    expect(button).toBeDisabled();
    expect(button).toHaveStyle({ opacity: '0.6' });
  });

  it('shows loading state during authentication', async () => {
    // Mock a delayed response
    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    // Should show loading state
    await waitFor(() => {
      expect(screen.getByText('Signing in...')).toBeInTheDocument();
      expect(button).toBeDisabled();
    });
  });

  it('handles successful Apple login', async () => {
    const mockAuthData = {
      authorization: {
        id_token: 'mock-id-token',
      },
    };

    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockResolvedValue(mockAuthData);

    const mockAppleAuthService = AppleAuthService as jest.MockedClass<typeof AppleAuthService>;
    mockAppleAuthService.prototype.verifyAppleToken = jest.fn().mockResolvedValue(mockUser);

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockAppleID.auth.init).toHaveBeenCalledWith({
        clientId: 'test.client.id',
        scope: 'name email',
        redirectURI: 'https://test.example.com',
        state: expect.any(String),
        usePopup: true,
      });
    });

    await waitFor(() => {
      expect(mockAppleID.auth.signIn).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(mockOnSuccess).toHaveBeenCalledWith(mockUser);
    });

    expect(mockOnError).not.toHaveBeenCalled();
  });

  it('handles Apple ID SDK not loaded error', async () => {
    // Remove AppleID from window
    delete (window as any).AppleID;

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockOnError).toHaveBeenCalledWith('Apple ID SDK not loaded');
    });

    expect(mockOnSuccess).not.toHaveBeenCalled();

    // Restore AppleID for other tests
    (window as any).AppleID = mockAppleID;
  });

  it('handles Apple ID initialization error', async () => {
    const initError = new Error('Initialization failed');
    mockAppleID.auth.init.mockRejectedValue(initError);

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockOnError).toHaveBeenCalledWith('Initialization failed');
    });

    expect(mockOnSuccess).not.toHaveBeenCalled();
  });

  it('handles Apple sign in error', async () => {
    const signInError = new Error('Sign in failed');
    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockRejectedValue(signInError);

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockOnError).toHaveBeenCalledWith('Sign in failed');
    });

    expect(mockOnSuccess).not.toHaveBeenCalled();
  });

  it('handles token verification error', async () => {
    const mockAuthData = {
      authorization: {
        id_token: 'mock-id-token',
      },
    };

    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockResolvedValue(mockAuthData);

    const mockAppleAuthService = AppleAuthService as jest.MockedClass<typeof AppleAuthService>;
    mockAppleAuthService.prototype.verifyAppleToken = jest.fn().mockRejectedValue(new Error('Token verification failed'));

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockOnError).toHaveBeenCalledWith('Token verification failed');
    });

    expect(mockOnSuccess).not.toHaveBeenCalled();
  });

  it('generates random state for each login attempt', async () => {
    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockResolvedValue({
      authorization: { id_token: 'token' },
    });

    const mockAppleAuthService = AppleAuthService as jest.MockedClass<typeof AppleAuthService>;
    mockAppleAuthService.prototype.verifyAppleToken = jest.fn().mockResolvedValue(mockUser);

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    
    // First click
    fireEvent.click(button);
    await waitFor(() => expect(mockAppleID.auth.init).toHaveBeenCalledTimes(1));
    const firstState = mockAppleID.auth.init.mock.calls[0][0].state;

    // Reset mocks
    mockAppleID.auth.init.mockClear();
    mockOnSuccess.mockClear();

    // Second click
    fireEvent.click(button);
    await waitFor(() => expect(mockAppleID.auth.init).toHaveBeenCalledTimes(1));
    const secondState = mockAppleID.auth.init.mock.calls[0][0].state;

    // States should be different
    expect(firstState).not.toBe(secondState);
    expect(firstState).toMatch(/^[a-z0-9]+$/);
    expect(secondState).toMatch(/^[a-z0-9]+$/);
  });

  it('uses default values when environment variables are not set', async () => {
    process.env.REACT_APP_APPLE_CLIENT_ID = '';
    process.env.REACT_APP_APPLE_REDIRECT_URI = '';

    mockAppleID.auth.init.mockResolvedValue(undefined);
    mockAppleID.auth.signIn.mockResolvedValue({
      authorization: { id_token: 'token' },
    });

    const mockAppleAuthService = AppleAuthService as jest.MockedClass<typeof AppleAuthService>;
    mockAppleAuthService.prototype.verifyAppleToken = jest.fn().mockResolvedValue(mockUser);

    render(
      <AppleLoginButton onSuccess={mockOnSuccess} onError={mockOnError} />
    );

    const button = screen.getByRole('button');
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockAppleID.auth.init).toHaveBeenCalledWith({
        clientId: 'your.app.bundle.id',
        scope: 'name email',
        redirectURI: window.location.origin,
        state: expect.any(String),
        usePopup: true,
      });
    });
  });
});