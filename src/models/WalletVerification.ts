/**
 * Wallet Verification Models
 * 
 * Type definitions for Apple Wallet "Verify with Wallet" functionality
 * Supporting age verification, identity verification, and address verification
 * for use cases like liquor purchases, car rentals, etc.
 */

// Base verification types
export type VerificationType = 'age' | 'identity' | 'address' | 'combined';
export type VerificationPurpose = 
  | 'liquor_purchase' 
  | 'car_rental' 
  | 'age_restricted_content' 
  | 'identity_verification'
  | 'address_confirmation'
  | 'custom';

export type VerificationStatus = 
  | 'pending' 
  | 'in_progress' 
  | 'verified' 
  | 'failed' 
  | 'cancelled' 
  | 'expired';

// Device and browser capability detection
export interface WalletCapabilities {
  supportsDigitalCredentials: boolean;
  supportsPassKit: boolean;
  isIOSDevice: boolean;
  iOSVersion?: string;
  browserSupported: boolean;
  hasWalletApp: boolean;
}

// Core verification request structure
export interface WalletVerificationRequest {
  // What type of verification is needed
  type: VerificationType;
  
  // Why this verification is needed (for user consent)
  purpose: VerificationPurpose;
  purposeDescription?: string;
  
  // Age verification specific
  minAge?: number;
  maxAge?: number;
  
  // Required fields to verify
  requiredFields: VerificationField[];
  
  // Optional fields that would be helpful
  optionalFields?: VerificationField[];
  
  // Merchant/app information
  merchantInfo: {
    name: string;
    category: string;
    identifier: string;
  };
  
  // Request metadata
  requestId: string;
  timestamp: Date;
  expiresAt?: Date;
  
  // Privacy and consent
  dataUsageDescription: string;
  retentionPolicy?: string;
}

// Fields that can be verified via wallet
export type VerificationField = 
  | 'age'
  | 'date_of_birth'
  | 'first_name'
  | 'last_name'
  | 'full_name'
  | 'address'
  | 'city'
  | 'state'
  | 'postal_code'
  | 'country'
  | 'document_number'
  | 'document_type'
  | 'issuing_authority';

// Verified data returned from wallet
export interface VerifiedCredentials {
  // Age verification results
  age?: number;
  isOver18?: boolean;
  isOver21?: boolean;
  isOver25?: boolean;
  dateOfBirth?: string; // ISO date string, may be partial for privacy
  
  // Identity verification results
  firstName?: string;
  lastName?: string;
  fullName?: string;
  
  // Address verification results
  address?: {
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
  };
  
  // Document information (if shared)
  document?: {
    type: 'drivers_license' | 'state_id' | 'passport' | 'other';
    issuingAuthority?: string;
    expirationDate?: string;
    verified: boolean;
  };
  
  // Verification metadata
  verificationLevel: 'basic' | 'enhanced' | 'full';
  verifiedAt: Date;
  verificationMethod: 'apple_wallet' | 'manual_review' | 'fallback';
}

// Main response from wallet verification
export interface WalletVerificationResponse {
  success: boolean;
  status: VerificationStatus;
  
  // Verification results
  verified: boolean;
  credentials?: VerifiedCredentials;
  
  // Transaction tracking
  transactionId: string;
  requestId: string;
  
  // Error information
  error?: {
    code: string;
    message: string;
    details?: string;
    retryable: boolean;
  };
  
  // Metadata
  completedAt: Date;
  processingTimeMs: number;
  
  // Privacy and audit
  auditTrail?: {
    userConsented: boolean;
    dataMinimized: boolean;
    purposeLimited: boolean;
  };
}

// Digital Credentials API request (W3C standard)
export interface DigitalCredentialRequest {
  // Standard W3C Digital Credentials API fields
  types: string[];
  
  // Apple-specific extensions
  apple?: {
    scope: string[];
    purpose: string;
    merchantIdentifier: string;
  };
  
  // Request options
  signal?: AbortSignal;
  mediation?: 'required' | 'optional' | 'silent';
}

// Digital Credentials API response
export interface DigitalCredentialResponse {
  id: string;
  type: string;
  data: any; // Will be parsed based on credential type
  authenticatorData?: ArrayBuffer;
  clientDataJSON?: ArrayBuffer;
}

// Error types specific to wallet verification
export class WalletVerificationError extends Error {
  constructor(
    message: string,
    public readonly code: WalletErrorCode,
    public readonly retryable: boolean = false,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'WalletVerificationError';
  }
}

export type WalletErrorCode = 
  | 'UNSUPPORTED_DEVICE'
  | 'UNSUPPORTED_BROWSER'
  | 'WALLET_NOT_AVAILABLE'
  | 'NO_CREDENTIALS'
  | 'USER_CANCELLED'
  | 'PERMISSION_DENIED'
  | 'NETWORK_ERROR'
  | 'INVALID_REQUEST'
  | 'VERIFICATION_FAILED'
  | 'EXPIRED_REQUEST'
  | 'RATE_LIMITED'
  | 'SERVER_ERROR'
  | 'UNKNOWN_ERROR';

// Configuration for wallet verification service
export interface WalletVerificationConfig {
  // API endpoints
  verifyEndpoint: string;
  statusEndpoint: string;
  
  // Timeouts
  requestTimeoutMs: number;
  verificationTimeoutMs: number;
  
  // Retry configuration
  maxRetries: number;
  retryDelayMs: number;
  
  // Feature flags
  enableFallback: boolean;
  enableAnalytics: boolean;
  enableAuditLogging: boolean;
  
  // Privacy settings
  dataRetentionDays: number;
  minimizeData: boolean;
}

// Analytics and tracking
export interface WalletVerificationAnalytics {
  // Event tracking
  eventType: 'started' | 'completed' | 'failed' | 'cancelled';
  
  // Request details
  verificationType: VerificationType;
  purpose: VerificationPurpose;
  
  // Device information
  deviceType: string;
  osVersion: string;
  browserInfo: string;
  
  // Performance metrics
  durationMs: number;
  retryCount: number;
  
  // Results
  success: boolean;
  errorCode?: WalletErrorCode;
  
  // Privacy compliant metadata
  timestamp: Date;
  sessionId: string;
}

// Utility builder class for creating verification requests
export class WalletVerificationRequestBuilder {
  private request: Partial<WalletVerificationRequest> = {
    requiredFields: [],
    optionalFields: [],
    timestamp: new Date()
  };

  setType(type: VerificationType): WalletVerificationRequestBuilder {
    this.request.type = type;
    return this;
  }

  setPurpose(purpose: VerificationPurpose, description?: string): WalletVerificationRequestBuilder {
    this.request.purpose = purpose;
    this.request.purposeDescription = description;
    return this;
  }

  setAgeRequirement(minAge: number, maxAge?: number): WalletVerificationRequestBuilder {
    this.request.minAge = minAge;
    this.request.maxAge = maxAge;
    return this;
  }

  addRequiredField(field: VerificationField): WalletVerificationRequestBuilder {
    if (!this.request.requiredFields?.includes(field)) {
      this.request.requiredFields?.push(field);
    }
    return this;
  }

  addOptionalField(field: VerificationField): WalletVerificationRequestBuilder {
    if (!this.request.optionalFields) {
      this.request.optionalFields = [];
    }
    if (!this.request.optionalFields.includes(field)) {
      this.request.optionalFields.push(field);
    }
    return this;
  }

  setMerchantInfo(name: string, category: string, identifier: string): WalletVerificationRequestBuilder {
    this.request.merchantInfo = { name, category, identifier };
    return this;
  }

  setDataUsage(description: string, retentionPolicy?: string): WalletVerificationRequestBuilder {
    this.request.dataUsageDescription = description;
    this.request.retentionPolicy = retentionPolicy;
    return this;
  }

  setExpiration(expiresAt: Date): WalletVerificationRequestBuilder {
    this.request.expiresAt = expiresAt;
    return this;
  }

  build(): WalletVerificationRequest {
    // Generate request ID if not provided
    if (!this.request.requestId) {
      this.request.requestId = this.generateRequestId();
    }

    // Validate required fields
    if (!this.request.type) {
      throw new Error('Verification type is required');
    }
    if (!this.request.purpose) {
      throw new Error('Verification purpose is required');
    }
    if (!this.request.merchantInfo) {
      throw new Error('Merchant information is required');
    }
    if (!this.request.dataUsageDescription) {
      throw new Error('Data usage description is required');
    }
    if (!this.request.requiredFields || this.request.requiredFields.length === 0) {
      throw new Error('At least one required field must be specified');
    }

    return this.request as WalletVerificationRequest;
  }

  private generateRequestId(): string {
    return `wallet_verify_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }
}

// Predefined common verification scenarios
export class WalletVerificationPresets {
  
  static liquorPurchase(merchantName: string, merchantId: string): WalletVerificationRequest {
    return new WalletVerificationRequestBuilder()
      .setType('age')
      .setPurpose('liquor_purchase', 'Verify that you are 21 or older to purchase alcohol')
      .setAgeRequirement(21)
      .addRequiredField('age')
      .setMerchantInfo(merchantName, 'liquor_store', merchantId)
      .setDataUsage('Age verification for alcohol purchase. Data is not stored after verification.')
      .build();
  }

  static carRental(merchantName: string, merchantId: string): WalletVerificationRequest {
    return new WalletVerificationRequestBuilder()
      .setType('combined')
      .setPurpose('car_rental', 'Verify your age and identity for car rental')
      .setAgeRequirement(25)
      .addRequiredField('age')
      .addRequiredField('first_name')
      .addRequiredField('last_name')
      .addOptionalField('address')
      .setMerchantInfo(merchantName, 'car_rental', merchantId)
      .setDataUsage('Identity and age verification for car rental. Data used only for this transaction.')
      .build();
  }

  static ageVerification(minAge: number, merchantName: string, merchantId: string): WalletVerificationRequest {
    return new WalletVerificationRequestBuilder()
      .setType('age')
      .setPurpose('age_restricted_content', `Verify that you are ${minAge} or older`)
      .setAgeRequirement(minAge)
      .addRequiredField('age')
      .setMerchantInfo(merchantName, 'age_restricted', merchantId)
      .setDataUsage(`Age verification for access to ${minAge}+ content. No personal data is stored.`)
      .build();
  }

  static identityVerification(merchantName: string, merchantId: string): WalletVerificationRequest {
    return new WalletVerificationRequestBuilder()
      .setType('identity')
      .setPurpose('identity_verification', 'Verify your identity')
      .addRequiredField('first_name')
      .addRequiredField('last_name')
      .addOptionalField('address')
      .setMerchantInfo(merchantName, 'identity_services', merchantId)
      .setDataUsage('Identity verification. Data used only for verification and not stored long-term.')
      .build();
  }
}