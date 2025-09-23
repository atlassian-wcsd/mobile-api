/**
 * Models Index
 * 
 * Central export file for all authentication and verification models
 */

// Apple Authentication Models
export * from './AppleUser';

// Wallet Verification Models
export * from './WalletVerification';

// Unified Authentication Models
export * from './AuthenticationTypes';

// Signature Models (existing)
export * from './Signature';

// Type guards and utilities
export class ModelUtils {
  
  static isAppleUser(obj: any): obj is import('./AppleUser').AppleUser {
    return obj && 
           typeof obj.id === 'string' && 
           typeof obj.authToken === 'string' &&
           obj.expiresAt instanceof Date;
  }

  static isWalletVerificationResponse(obj: any): obj is import('./WalletVerification').WalletVerificationResponse {
    return obj && 
           typeof obj.success === 'boolean' &&
           typeof obj.verified === 'boolean' &&
           typeof obj.transactionId === 'string';
  }

  static hasWalletVerification(user: import('./AppleUser').AppleUser): boolean {
    return Boolean(user.walletVerified && user.verifiedCredentials);
  }

  static getVerificationLevel(user: import('./AppleUser').AppleUser): 'none' | 'basic' | 'enhanced' | 'full' {
    if (!user.walletVerified || !user.verifiedCredentials) {
      return 'none';
    }
    return user.verifiedCredentials.verificationLevel || 'basic';
  }
}