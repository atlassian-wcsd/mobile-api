/**
 * Unified Authentication Types
 * 
 * Combined type definitions for Apple Login and Wallet Verification
 * to support integrated authentication flows
 */

import { AppleUser } from './AppleUser';
import { WalletVerificationRequest, WalletVerificationResponse, VerificationType } from './WalletVerification';

// Combined authentication methods
export type AuthenticationMethod = 'apple_id' | 'wallet_verify' | 'combined';

// Enhanced authentication context
export interface AuthenticationContext {
  method: AuthenticationMethod;
  timestamp: Date;
  sessionId: string;
  deviceInfo: {
    userAgent: string;
    platform: string;
    isIOSDevice: boolean;
    supportsWallet: boolean;
  };
}

// Unified authentication request
export interface UnifiedAuthRequest {
  // Primary authentication (Apple ID)
  primaryAuth: {
    method: 'apple_id';
    skipIfAuthenticated?: boolean;
  };
  
  // Secondary verification (Wallet)
  secondaryVerification?: {
    required: boolean;
    type: VerificationType;
    request: WalletVerificationRequest;
  };
  
  // Flow configuration
  flowConfig: {
    allowPartialAuth: boolean;
    requireVerification: boolean;
    fallbackToManual: boolean;
  };
  
  context: AuthenticationContext;
}

// Unified authentication response
export interface UnifiedAuthResponse {
  success: boolean;
  
  // Authentication results
  user?: AppleUser;
  authenticationLevel: 'basic' | 'verified' | 'enhanced';
  
  // Verification results
  walletVerification?: WalletVerificationResponse;
  
  // Flow status
  status: 'completed' | 'partial' | 'failed' | 'requires_verification';
  nextStep?: 'wallet_verify' | 'manual_verify' | 'complete';
  
  // Session information
  sessionToken?: string;
  expiresAt?: Date;
  
  // Error information
  errors?: AuthenticationError[];
  
  context: AuthenticationContext;
}

// Authentication error with context
export interface AuthenticationError {
  code: string;
  message: string;
  type: 'apple_auth' | 'wallet_verify' | 'system';
  retryable: boolean;
  details?: any;
}

// Authentication state for UI components
export interface AuthenticationState {
  // Loading states
  isLoading: boolean;
  isAppleAuthLoading: boolean;
  isWalletVerifyLoading: boolean;
  
  // Authentication status
  isAuthenticated: boolean;
  isVerified: boolean;
  user?: AppleUser;
  
  // Verification status
  verificationStatus?: 'pending' | 'in_progress' | 'completed' | 'failed';
  verificationResults?: WalletVerificationResponse;
  
  // Error states
  error?: string;
  authError?: AuthenticationError;
  
  // Capabilities
  canUseAppleAuth: boolean;
  canUseWalletVerify: boolean;
  
  // Flow control
  currentStep: 'login' | 'verify' | 'complete';
  showFallback: boolean;
}

// Configuration for authentication flows
export interface AuthFlowConfig {
  // Apple ID configuration
  appleAuth: {
    enabled: boolean;
    clientId: string;
    redirectURI: string;
    scope: string[];
  };
  
  // Wallet verification configuration
  walletVerify: {
    enabled: boolean;
    required: boolean;
    supportedTypes: VerificationType[];
    fallbackEnabled: boolean;
  };
  
  // UI configuration
  ui: {
    showAppleButton: boolean;
    showWalletButton: boolean;
    showCombinedFlow: boolean;
    allowSkipVerification: boolean;
  };
  
  // Security configuration
  security: {
    requireVerificationForSensitive: boolean;
    sessionTimeoutMinutes: number;
    maxRetries: number;
  };
}

// Actions for authentication state management
export type AuthAction = 
  | { type: 'APPLE_AUTH_START' }
  | { type: 'APPLE_AUTH_SUCCESS'; payload: AppleUser }
  | { type: 'APPLE_AUTH_ERROR'; payload: string }
  | { type: 'WALLET_VERIFY_START' }
  | { type: 'WALLET_VERIFY_SUCCESS'; payload: WalletVerificationResponse }
  | { type: 'WALLET_VERIFY_ERROR'; payload: string }
  | { type: 'SET_STEP'; payload: AuthenticationState['currentStep'] }
  | { type: 'RESET_AUTH' }
  | { type: 'SET_CAPABILITIES'; payload: { canUseAppleAuth: boolean; canUseWalletVerify: boolean } };

// Predefined authentication flows
export class AuthFlowPresets {
  
  static basicAppleLogin(): AuthFlowConfig {
    return {
      appleAuth: {
        enabled: true,
        clientId: process.env.REACT_APP_APPLE_CLIENT_ID || '',
        redirectURI: process.env.REACT_APP_APPLE_REDIRECT_URI || '',
        scope: ['name', 'email']
      },
      walletVerify: {
        enabled: false,
        required: false,
        supportedTypes: [],
        fallbackEnabled: true
      },
      ui: {
        showAppleButton: true,
        showWalletButton: false,
        showCombinedFlow: false,
        allowSkipVerification: true
      },
      security: {
        requireVerificationForSensitive: false,
        sessionTimeoutMinutes: 60,
        maxRetries: 3
      }
    };
  }

  static verifiedLiquorPurchase(): AuthFlowConfig {
    return {
      appleAuth: {
        enabled: true,
        clientId: process.env.REACT_APP_APPLE_CLIENT_ID || '',
        redirectURI: process.env.REACT_APP_APPLE_REDIRECT_URI || '',
        scope: ['name', 'email']
      },
      walletVerify: {
        enabled: true,
        required: true,
        supportedTypes: ['age'],
        fallbackEnabled: true
      },
      ui: {
        showAppleButton: true,
        showWalletButton: true,
        showCombinedFlow: true,
        allowSkipVerification: false
      },
      security: {
        requireVerificationForSensitive: true,
        sessionTimeoutMinutes: 30,
        maxRetries: 3
      }
    };
  }

  static carRentalAuth(): AuthFlowConfig {
    return {
      appleAuth: {
        enabled: true,
        clientId: process.env.REACT_APP_APPLE_CLIENT_ID || '',
        redirectURI: process.env.REACT_APP_APPLE_REDIRECT_URI || '',
        scope: ['name', 'email']
      },
      walletVerify: {
        enabled: true,
        required: true,
        supportedTypes: ['combined'],
        fallbackEnabled: true
      },
      ui: {
        showAppleButton: true,
        showWalletButton: true,
        showCombinedFlow: true,
        allowSkipVerification: false
      },
      security: {
        requireVerificationForSensitive: true,
        sessionTimeoutMinutes: 120,
        maxRetries: 3
      }
    };
  }
}