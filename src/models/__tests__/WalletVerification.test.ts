/**
 * Wallet Verification Models Tests
 * 
 * Basic validation tests for the wallet verification models
 */

import {
  WalletVerificationRequestBuilder,
  WalletVerificationPresets,
  WalletVerificationError,
  ModelUtils
} from '../index';

// Test the builder pattern
describe('WalletVerificationRequestBuilder', () => {
  it('should build a basic age verification request', () => {
    const request = new WalletVerificationRequestBuilder()
      .setType('age')
      .setPurpose('liquor_purchase', 'Verify age for alcohol purchase')
      .setAgeRequirement(21)
      .addRequiredField('age')
      .setMerchantInfo('Test Store', 'liquor_store', 'test_store_123')
      .setDataUsage('Age verification only, no data stored')
      .build();

    expect(request.type).toBe('age');
    expect(request.purpose).toBe('liquor_purchase');
    expect(request.minAge).toBe(21);
    expect(request.requiredFields).toContain('age');
    expect(request.merchantInfo.name).toBe('Test Store');
    expect(request.requestId).toBeDefined();
    expect(request.timestamp).toBeInstanceOf(Date);
  });

  it('should throw error for incomplete request', () => {
    expect(() => {
      new WalletVerificationRequestBuilder()
        .setType('age')
        .build();
    }).toThrow('Verification purpose is required');
  });

  it('should generate unique request IDs', () => {
    const request1 = new WalletVerificationRequestBuilder()
      .setType('age')
      .setPurpose('liquor_purchase')
      .addRequiredField('age')
      .setMerchantInfo('Store 1', 'liquor_store', 'store1')
      .setDataUsage('Test')
      .build();

    const request2 = new WalletVerificationRequestBuilder()
      .setType('age')
      .setPurpose('liquor_purchase')
      .addRequiredField('age')
      .setMerchantInfo('Store 2', 'liquor_store', 'store2')
      .setDataUsage('Test')
      .build();

    expect(request1.requestId).not.toBe(request2.requestId);
  });
});

// Test the presets
describe('WalletVerificationPresets', () => {
  it('should create liquor purchase request correctly', () => {
    const request = WalletVerificationPresets.liquorPurchase('ABC Liquor', 'abc_123');
    
    expect(request.type).toBe('age');
    expect(request.purpose).toBe('liquor_purchase');
    expect(request.minAge).toBe(21);
    expect(request.requiredFields).toContain('age');
    expect(request.merchantInfo.name).toBe('ABC Liquor');
    expect(request.merchantInfo.identifier).toBe('abc_123');
    expect(request.dataUsageDescription).toContain('alcohol purchase');
  });

  it('should create car rental request correctly', () => {
    const request = WalletVerificationPresets.carRental('Rental Co', 'rental_456');
    
    expect(request.type).toBe('combined');
    expect(request.purpose).toBe('car_rental');
    expect(request.minAge).toBe(25);
    expect(request.requiredFields).toContain('age');
    expect(request.requiredFields).toContain('first_name');
    expect(request.requiredFields).toContain('last_name');
    expect(request.optionalFields).toContain('address');
  });

  it('should create age verification request correctly', () => {
    const request = WalletVerificationPresets.ageVerification(18, 'Content Site', 'site_789');
    
    expect(request.type).toBe('age');
    expect(request.purpose).toBe('age_restricted_content');
    expect(request.minAge).toBe(18);
    expect(request.dataUsageDescription).toContain('18+');
  });
});

// Test error handling
describe('WalletVerificationError', () => {
  it('should create error with correct properties', () => {
    const error = new WalletVerificationError(
      'Test error',
      'UNSUPPORTED_DEVICE',
      true
    );

    expect(error.message).toBe('Test error');
    expect(error.code).toBe('UNSUPPORTED_DEVICE');
    expect(error.retryable).toBe(true);
    expect(error.name).toBe('WalletVerificationError');
  });
});

// Test model utilities
describe('ModelUtils', () => {
  it('should validate AppleUser correctly', () => {
    const validUser = {
      id: 'user123',
      authToken: 'token123',
      expiresAt: new Date(),
      createdAt: new Date(),
      lastLoginAt: new Date()
    };

    const invalidUser = {
      id: 'user123'
      // missing required fields
    };

    expect(ModelUtils.isAppleUser(validUser)).toBe(true);
    expect(ModelUtils.isAppleUser(invalidUser)).toBe(false);
    expect(ModelUtils.isAppleUser(null)).toBe(false);
  });

  it('should check wallet verification status correctly', () => {
    const unverifiedUser = {
      id: 'user123',
      authToken: 'token123',
      expiresAt: new Date(),
      createdAt: new Date(),
      lastLoginAt: new Date()
    };

    const verifiedUser = {
      ...unverifiedUser,
      walletVerified: true,
      verifiedCredentials: {
        ageVerified: true,
        verificationLevel: 'enhanced' as const
      }
    };

    expect(ModelUtils.hasWalletVerification(unverifiedUser)).toBe(false);
    expect(ModelUtils.hasWalletVerification(verifiedUser)).toBe(true);
    expect(ModelUtils.getVerificationLevel(unverifiedUser)).toBe('none');
    expect(ModelUtils.getVerificationLevel(verifiedUser)).toBe('enhanced');
  });
});

// Mock data for testing
export const mockWalletVerificationRequest = new WalletVerificationRequestBuilder()
  .setType('age')
  .setPurpose('liquor_purchase', 'Test verification')
  .setAgeRequirement(21)
  .addRequiredField('age')
  .setMerchantInfo('Test Merchant', 'test', 'test_123')
  .setDataUsage('Test data usage')
  .build();

export const mockWalletVerificationResponse = {
  success: true,
  status: 'verified' as const,
  verified: true,
  credentials: {
    age: 25,
    isOver21: true,
    verificationLevel: 'enhanced' as const,
    verifiedAt: new Date(),
    verificationMethod: 'apple_wallet' as const
  },
  transactionId: 'txn_123456',
  requestId: mockWalletVerificationRequest.requestId,
  completedAt: new Date(),
  processingTimeMs: 1500,
  auditTrail: {
    userConsented: true,
    dataMinimized: true,
    purposeLimited: true
  }
};

export const mockAppleUserWithWallet = {
  id: 'apple_user_123',
  email: 'user@example.com',
  firstName: 'John',
  lastName: 'Doe',
  fullName: 'John Doe',
  authToken: 'apple_token_123',
  expiresAt: new Date(Date.now() + 3600000),
  createdAt: new Date(),
  lastLoginAt: new Date(),
  walletVerified: true,
  walletVerificationDate: new Date(),
  verifiedCredentials: {
    ageVerified: true,
    identityVerified: true,
    verificationLevel: 'enhanced' as const
  }
};