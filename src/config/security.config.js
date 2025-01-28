/**
 * Security Configuration
 * Implements security settings for mobile user authentication and data protection
 */

const securityConfig = {
  // Password strength requirements
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    prohibitedPasswords: ['password', '12345678', 'qwerty'],
    maxAge: 90 // days before password expires
  },

  // Multi-factor authentication settings
  mfa: {
    enabled: true,
    methods: ['sms', 'email', 'authenticator'],
    codeLength: 6,
    codeExpiry: 300, // seconds
    maxAttempts: 3
  },

  // Login attempt controls
  loginSecurity: {
    maxAttempts: 5,
    lockoutDuration: 900, // seconds (15 minutes)
    requireCaptcha: true,
    rateLimiting: {
      windowMs: 900000, // 15 minutes
      maxRequests: 100 // requests per windowMs
    }
  },

  // Password reset settings
  passwordReset: {
    tokenExpiry: 3600, // seconds (1 hour)
    requireSecurityQuestions: true,
    minimumSecurityQuestions: 2,
    notifyUserOnReset: true
  },

  // Session management
  session: {
    tokenExpiry: 3600, // seconds (1 hour)
    refreshTokenExpiry: 2592000, // seconds (30 days)
    maxConcurrentSessions: 3,
    renewOnActivity: true,
    absoluteTimeout: 86400 // seconds (24 hours)
  },

  // Security audit settings
  securityAudit: {
    enabled: true,
    auditFrequency: 'daily',
    retentionPeriod: 90, // days
    criticalEvents: [
      'login_failure',
      'password_reset',
      'mfa_change',
      'profile_update'
    ]
  },

  // Encryption settings
  encryption: {
    algorithm: 'AES-256-GCM',
    keyRotationPeriod: 30, // days
    saltRounds: 10,
    transportEncryption: {
      minTLSVersion: 'TLSv1.2',
      preferredCipherSuites: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256'
      ]
    }
  },

  // Compliance settings
  compliance: {
    gdpr: {
      enabled: true,
      dataRetentionPeriod: 730, // days (2 years)
      userDataAccessEnabled: true
    },
    ccpa: {
      enabled: true,
      doNotSellPersonalInfo: true
    }
  },

  // Activity logging
  logging: {
    enabled: true,
    logLevel: 'info',
    events: {
      login: true,
      logout: true,
      passwordChange: true,
      profileUpdate: true,
      mfaEvents: true
    },
    retention: {
      period: 365, // days
      storageType: 'encrypted'
    }
  }
};

// Freeze the configuration to prevent runtime modifications
Object.freeze(securityConfig);

module.exports = securityConfig;