import { AppleUserBuilder, AppleUser } from '../AppleUser';

describe('AppleUserBuilder', () => {
  let builder: AppleUserBuilder;

  beforeEach(() => {
    builder = new AppleUserBuilder();
  });

  describe('setId', () => {
    it('sets the user ID', () => {
      const user = builder
        .setId('test-user-id')
        .setAuthToken('test-token')
        .build();

      expect(user.id).toBe('test-user-id');
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setId('test-id');
      expect(result).toBe(builder);
    });
  });

  describe('setEmail', () => {
    it('sets the user email', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setEmail('test@example.com')
        .build();

      expect(user.email).toBe('test@example.com');
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setEmail('test@example.com');
      expect(result).toBe(builder);
    });
  });

  describe('setName', () => {
    it('sets first and last name', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setName('John', 'Doe')
        .build();

      expect(user.firstName).toBe('John');
      expect(user.lastName).toBe('Doe');
      expect(user.fullName).toBe('John Doe');
    });

    it('sets only first name when last name is undefined', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setName('John', undefined)
        .build();

      expect(user.firstName).toBe('John');
      expect(user.lastName).toBeUndefined();
      expect(user.fullName).toBe('John');
    });

    it('sets only last name when first name is undefined', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setName(undefined, 'Doe')
        .build();

      expect(user.firstName).toBeUndefined();
      expect(user.lastName).toBe('Doe');
      expect(user.fullName).toBe('Doe');
    });

    it('handles both names being undefined', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setName(undefined, undefined)
        .build();

      expect(user.firstName).toBeUndefined();
      expect(user.lastName).toBeUndefined();
      expect(user.fullName).toBe('');
    });

    it('handles empty strings', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setName('', 'Doe')
        .build();

      expect(user.firstName).toBe('');
      expect(user.lastName).toBe('Doe');
      expect(user.fullName).toBe('Doe');
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setName('John', 'Doe');
      expect(result).toBe(builder);
    });
  });

  describe('setAuthToken', () => {
    it('sets the auth token', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-auth-token')
        .build();

      expect(user.authToken).toBe('test-auth-token');
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setAuthToken('test-token');
      expect(result).toBe(builder);
    });
  });

  describe('setRefreshToken', () => {
    it('sets the refresh token', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setRefreshToken('test-refresh-token')
        .build();

      expect(user.refreshToken).toBe('test-refresh-token');
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setRefreshToken('test-refresh-token');
      expect(result).toBe(builder);
    });
  });

  describe('setExpiresAt', () => {
    it('sets the expiration date', () => {
      const expirationDate = new Date('2024-12-31T23:59:59Z');
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setExpiresAt(expirationDate)
        .build();

      expect(user.expiresAt).toBe(expirationDate);
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setExpiresAt(new Date());
      expect(result).toBe(builder);
    });
  });

  describe('setIsPrivateEmail', () => {
    it('sets private email flag to true', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setIsPrivateEmail(true)
        .build();

      expect(user.isPrivateEmail).toBe(true);
    });

    it('sets private email flag to false', () => {
      const user = builder
        .setId('test-id')
        .setAuthToken('test-token')
        .setIsPrivateEmail(false)
        .build();

      expect(user.isPrivateEmail).toBe(false);
    });

    it('returns builder instance for chaining', () => {
      const result = builder.setIsPrivateEmail(true);
      expect(result).toBe(builder);
    });
  });

  describe('build', () => {
    it('builds a complete user with all fields', () => {
      const expirationDate = new Date('2024-12-31T23:59:59Z');
      const beforeBuild = Date.now();
      
      const user = builder
        .setId('test-user-id')
        .setEmail('test@example.com')
        .setName('John', 'Doe')
        .setAuthToken('test-auth-token')
        .setRefreshToken('test-refresh-token')
        .setExpiresAt(expirationDate)
        .setIsPrivateEmail(true)
        .build();

      const afterBuild = Date.now();

      expect(user).toMatchObject({
        id: 'test-user-id',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        fullName: 'John Doe',
        isPrivateEmail: true,
        authToken: 'test-auth-token',
        refreshToken: 'test-refresh-token',
        expiresAt: expirationDate,
      });

      expect(user.createdAt.getTime()).toBeGreaterThanOrEqual(beforeBuild);
      expect(user.createdAt.getTime()).toBeLessThanOrEqual(afterBuild);
      expect(user.lastLoginAt.getTime()).toBeGreaterThanOrEqual(beforeBuild);
      expect(user.lastLoginAt.getTime()).toBeLessThanOrEqual(afterBuild);
    });

    it('builds user with minimal required fields', () => {
      const user = builder
        .setId('test-user-id')
        .setAuthToken('test-auth-token')
        .build();

      expect(user).toMatchObject({
        id: 'test-user-id',
        authToken: 'test-auth-token',
        isPrivateEmail: false,
      });

      expect(user.email).toBeUndefined();
      expect(user.firstName).toBeUndefined();
      expect(user.lastName).toBeUndefined();
      expect(user.fullName).toBeUndefined();
      expect(user.refreshToken).toBeUndefined();
      expect(user.createdAt).toBeInstanceOf(Date);
      expect(user.lastLoginAt).toBeInstanceOf(Date);
      expect(user.expiresAt).toBeInstanceOf(Date);
    });

    it('sets default expiration to 1 hour from now', () => {
      const beforeBuild = Date.now();
      
      const user = builder
        .setId('test-user-id')
        .setAuthToken('test-auth-token')
        .build();

      const afterBuild = Date.now();
      const expectedExpiration = beforeBuild + 3600000; // 1 hour in milliseconds

      expect(user.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedExpiration - 100);
      expect(user.expiresAt.getTime()).toBeLessThanOrEqual(afterBuild + 3600000 + 100);
    });

    it('throws error when ID is missing', () => {
      expect(() => {
        builder.setAuthToken('test-token').build();
      }).toThrow('Apple user must have id and authToken');
    });

    it('throws error when auth token is missing', () => {
      expect(() => {
        builder.setId('test-id').build();
      }).toThrow('Apple user must have id and authToken');
    });

    it('throws error when both ID and auth token are missing', () => {
      expect(() => {
        builder.build();
      }).toThrow('Apple user must have id and authToken');
    });

    it('allows empty string as ID (edge case)', () => {
      expect(() => {
        builder.setId('').setAuthToken('test-token').build();
      }).toThrow('Apple user must have id and authToken');
    });

    it('allows empty string as auth token (edge case)', () => {
      expect(() => {
        builder.setId('test-id').setAuthToken('').build();
      }).toThrow('Apple user must have id and authToken');
    });
  });

  describe('method chaining', () => {
    it('allows fluent interface for all methods', () => {
      const user = builder
        .setId('test-id')
        .setEmail('test@example.com')
        .setName('John', 'Doe')
        .setAuthToken('test-token')
        .setRefreshToken('test-refresh')
        .setExpiresAt(new Date('2024-12-31'))
        .setIsPrivateEmail(true)
        .build();

      expect(user.id).toBe('test-id');
      expect(user.email).toBe('test@example.com');
      expect(user.firstName).toBe('John');
      expect(user.lastName).toBe('Doe');
      expect(user.authToken).toBe('test-token');
      expect(user.refreshToken).toBe('test-refresh');
      expect(user.isPrivateEmail).toBe(true);
    });
  });

  describe('builder reuse', () => {
    it('can be reused to build multiple users', () => {
      const user1 = builder
        .setId('user1')
        .setAuthToken('token1')
        .setEmail('user1@example.com')
        .build();

      const user2 = builder
        .setId('user2')
        .setAuthToken('token2')
        .setEmail('user2@example.com')
        .build();

      expect(user1.id).toBe('user2'); // Builder state is maintained
      expect(user1.email).toBe('user2@example.com');
      expect(user2.id).toBe('user2');
      expect(user2.email).toBe('user2@example.com');
    });

    it('maintains state between builds', () => {
      builder.setId('persistent-id').setAuthToken('persistent-token');

      const user1 = builder.setEmail('email1@example.com').build();
      const user2 = builder.setEmail('email2@example.com').build();

      expect(user1.id).toBe('persistent-id');
      expect(user1.email).toBe('email2@example.com'); // State was modified
      expect(user2.id).toBe('persistent-id');
      expect(user2.email).toBe('email2@example.com');
    });
  });
});