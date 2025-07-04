import React, { useState } from 'react';
import { AppleAuthService } from '../services/AppleAuthService';
import { AppleUser } from '../models/AppleUser';

interface AppleLoginButtonProps {
  onSuccess: (user: AppleUser) => void;
  onError: (error: string) => void;
  disabled?: boolean;
  className?: string;
}

export const AppleLoginButton: React.FC<AppleLoginButtonProps> = ({
  onSuccess,
  onError,
  disabled = false,
  className = ''
}) => {
  const [isLoading, setIsLoading] = useState(false);

  const handleAppleLogin = async () => {
    setIsLoading(true);
    
    try {
      // Initialize Apple ID authentication
      if (!window.AppleID) {
        throw new Error('Apple ID SDK not loaded');
      }

      // Configure Apple ID
      await window.AppleID.auth.init({
        clientId: process.env.REACT_APP_APPLE_CLIENT_ID || 'your.app.bundle.id',
        scope: 'name email',
        redirectURI: process.env.REACT_APP_APPLE_REDIRECT_URI || window.location.origin,
        state: generateRandomState(),
        usePopup: true
      });

      // Perform Apple ID sign in
      const data = await window.AppleID.auth.signIn();
      
      // Verify the token with our backend
      const appleAuthService = new AppleAuthService();
      const user = await appleAuthService.verifyAppleToken(data.authorization.id_token);
      
      onSuccess(user);
    } catch (error) {
      console.error('Apple Login failed:', error);
      onError(error instanceof Error ? error.message : 'Apple Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const generateRandomState = (): string => {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  };

  return (
    <button
      onClick={handleAppleLogin}
      disabled={disabled || isLoading}
      className={`apple-login-button ${className}`}
      style={{
        backgroundColor: '#000',
        color: '#fff',
        border: 'none',
        borderRadius: '6px',
        padding: '12px 16px',
        fontSize: '16px',
        fontWeight: '500',
        cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        minWidth: '200px',
        opacity: disabled || isLoading ? 0.6 : 1,
        transition: 'opacity 0.2s ease'
      }}
    >
      {isLoading ? (
        <>
          <div className="spinner" style={{
            width: '16px',
            height: '16px',
            border: '2px solid #ffffff40',
            borderTop: '2px solid #ffffff',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite'
          }} />
          Signing in...
        </>
      ) : (
        <>
          <AppleIcon />
          Sign in with Apple
        </>
      )}
    </button>
  );
};

const AppleIcon: React.FC = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
  </svg>
);

// Extend Window interface for Apple ID SDK
declare global {
  interface Window {
    AppleID: {
      auth: {
        init: (config: any) => Promise<void>;
        signIn: () => Promise<any>;
      };
    };
  }
}