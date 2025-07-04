import React, { useState, useCallback, useMemo } from 'react';
import { AppleAuthService } from '../services/AppleAuthService';
import { AppleUser } from '../models/AppleUser';

interface AppleLoginButtonProps {
  onSuccess: (user: AppleUser) => void;
  onError: (error: string) => void;
  disabled?: boolean;
  className?: string;
  variant?: 'default' | 'white' | 'black';
  size?: 'small' | 'medium' | 'large';
}

// Configuration validation
const validateConfig = () => {
  const clientId = process.env.REACT_APP_APPLE_CLIENT_ID;
  const redirectURI = process.env.REACT_APP_APPLE_REDIRECT_URI;
  
  if (!clientId) {
    throw new Error('REACT_APP_APPLE_CLIENT_ID is required');
  }
  if (!redirectURI) {
    throw new Error('REACT_APP_APPLE_REDIRECT_URI is required');
  }
  
  return { clientId, redirectURI };
};

// Secure state generation using crypto API
const generateSecureState = (): string => {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  // Fallback for older browsers
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15) + 
         Date.now().toString(36);
};

export const AppleLoginButton: React.FC<AppleLoginButtonProps> = ({
  onSuccess,
  onError,
  disabled = false,
  className = '',
  variant = 'default',
  size = 'medium'
}) => {
  const [isLoading, setIsLoading] = useState(false);
  
  // Memoize service instance
  const appleAuthService = useMemo(() => new AppleAuthService(), []);
  
  // Memoize configuration
  const config = useMemo(() => {
    try {
      return validateConfig();
    } catch (error) {
      console.error('Apple Login configuration error:', error);
      return null;
    }
  }, []);

  const handleAppleLogin = useCallback(async () => {
    if (!config) {
      onError('Apple Login is not properly configured');
      return;
    }

    setIsLoading(true);
    
    try {
      // Check Apple ID SDK availability
      if (!window.AppleID) {
        throw new Error('Apple ID SDK not loaded. Please ensure the Apple ID script is included.');
      }

      // Configure Apple ID with secure state
      await window.AppleID.auth.init({
        clientId: config.clientId,
        scope: 'name email',
        redirectURI: config.redirectURI,
        state: generateSecureState(),
        usePopup: true
      });

      // Perform Apple ID sign in
      const data = await window.AppleID.auth.signIn();
      
      // Verify the token with our backend
      const user = await appleAuthService.verifyAppleToken(
        data.authorization.id_token,
        data.authorization.code,
        data.user
      );
      
      onSuccess(user);
    } catch (error) {
      console.error('Apple Login failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Apple Login failed';
      onError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  }, [config, appleAuthService, onSuccess, onError]);

  // Don't render if not configured
  if (!config) {
    return null;
  }

  return (
    <AppleButton
      onClick={handleAppleLogin}
      disabled={disabled || isLoading}
      isLoading={isLoading}
      variant={variant}
      size={size}
      className={className}
    />
  );
};

// Separate styled button component for better maintainability
interface AppleButtonProps {
  onClick: () => void;
  disabled: boolean;
  isLoading: boolean;
  variant: 'default' | 'white' | 'black';
  size: 'small' | 'medium' | 'large';
  className: string;
}

const AppleButton: React.FC<AppleButtonProps> = ({
  onClick,
  disabled,
  isLoading,
  variant,
  size,
  className
}) => {
  const buttonStyles = getButtonStyles(variant, size, disabled, isLoading);
  
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`apple-login-button ${className}`}
      style={buttonStyles}
      aria-label="Sign in with Apple"
    >
      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <>
          <AppleIcon />
          Sign in with Apple
        </>
      )}
    </button>
  );
};

// Extracted styling logic
const getButtonStyles = (variant: string, size: string, disabled: boolean, isLoading: boolean) => {
  const baseStyles = {
    border: 'none',
    borderRadius: '6px',
    fontWeight: '500' as const,
    cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
    display: 'flex' as const,
    alignItems: 'center' as const,
    justifyContent: 'center' as const,
    gap: '8px',
    opacity: disabled || isLoading ? 0.6 : 1,
    transition: 'all 0.2s ease'
  };

  const variantStyles = {
    default: { backgroundColor: '#000', color: '#fff' },
    black: { backgroundColor: '#000', color: '#fff' },
    white: { backgroundColor: '#fff', color: '#000', border: '1px solid #d1d5db' }
  };

  const sizeStyles = {
    small: { padding: '8px 12px', fontSize: '14px', minWidth: '160px' },
    medium: { padding: '12px 16px', fontSize: '16px', minWidth: '200px' },
    large: { padding: '16px 20px', fontSize: '18px', minWidth: '240px' }
  };

  return {
    ...baseStyles,
    ...variantStyles[variant],
    ...sizeStyles[size]
  };
};

const LoadingSpinner: React.FC = () => (
  <div 
    style={{
      width: '16px',
      height: '16px',
      border: '2px solid #ffffff40',
      borderTop: '2px solid #ffffff',
      borderRadius: '50%',
      animation: 'spin 1s linear infinite'
    }}
    aria-label="Loading"
  />
);

const AppleIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
  </svg>
);

// Enhanced type definitions
declare global {
  interface Window {
    AppleID: {
      auth: {
        init: (config: AppleIDConfig) => Promise<void>;
        signIn: () => Promise<AppleIDSignInResponse>;
      };
    };
  }
}

interface AppleIDConfig {
  clientId: string;
  scope: string;
  redirectURI: string;
  state: string;
  usePopup: boolean;
}

interface AppleIDSignInResponse {
  authorization: {
    id_token: string;
    code: string;
  };
  user?: {
    name?: {
      firstName: string;
      lastName: string;
    };
    email?: string;
  };
}