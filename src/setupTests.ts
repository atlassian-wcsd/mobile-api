import '@testing-library/jest-dom';

// Mock crypto.randomUUID for tests
Object.defineProperty(global, 'crypto', {
  value: {
    randomUUID: jest.fn(() => 'test-uuid-123'),
  },
});

// Mock window.location for tests
Object.defineProperty(window, 'location', {
  value: {
    origin: 'http://localhost:3000',
    href: 'http://localhost:3000',
    pathname: '/',
    search: '',
    hash: '',
  },
  writable: true,
});

// Mock navigator.userAgent for tests
Object.defineProperty(navigator, 'userAgent', {
  value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  writable: true,
});

// Mock console methods to reduce noise in tests
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeEach(() => {
  console.error = jest.fn();
  console.warn = jest.fn();
});

afterEach(() => {
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Global test utilities
global.testUtils = {
  createMockAppleUser: () => ({
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
  }),
  
  createMockSignature: () => ({
    id: 'test-signature-id',
    imageData: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
    width: 500,
    height: 200,
    createdAt: new Date('2024-01-01'),
    userId: 'test-user-id',
    metadata: {
      device: 'browser',
      platform: 'Chrome',
      pressureData: [],
    },
  }),
};

// Extend Jest matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidSignatureId(): R;
      toBeValidAppleUser(): R;
    }
  }
  
  var testUtils: {
    createMockAppleUser: () => any;
    createMockSignature: () => any;
  };
}

// Custom Jest matchers
expect.extend({
  toBeValidSignatureId(received: string) {
    const pass = /^sig_\d+_[a-z0-9]{9}$/.test(received);
    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid signature ID`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid signature ID (format: sig_timestamp_randomstring)`,
        pass: false,
      };
    }
  },
  
  toBeValidAppleUser(received: any) {
    const requiredFields = ['id', 'authToken', 'createdAt', 'lastLoginAt', 'expiresAt'];
    const missingFields = requiredFields.filter(field => !received || !received[field]);
    
    if (missingFields.length === 0) {
      return {
        message: () => `expected object not to be a valid Apple user`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected object to be a valid Apple user, missing fields: ${missingFields.join(', ')}`,
        pass: false,
      };
    }
  },
});

// Mock IntersectionObserver for components that might use it
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};

// Mock ResizeObserver for components that might use it
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};

// Mock requestAnimationFrame for animation tests
global.requestAnimationFrame = (callback: FrameRequestCallback) => {
  return setTimeout(callback, 0);
};

global.cancelAnimationFrame = (id: number) => {
  clearTimeout(id);
};