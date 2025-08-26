# Testing Guide for Signature Application

This document provides comprehensive information about the testing setup and how to run tests for the Signature Application.

## Overview

The application has a comprehensive test suite covering both frontend (React/TypeScript) and backend (Go) components:

- **Frontend Tests**: React component tests, service tests, and model tests using Jest and React Testing Library
- **Backend Tests**: Go unit tests using testify for Apple authentication and Lambda handlers
- **Integration Tests**: End-to-end testing scenarios
- **Coverage Reports**: Detailed coverage analysis for both frontend and backend

## Test Structure

```
├── src/
│   ├── components/__tests__/          # React component tests
│   ├── services/__tests__/            # Service layer tests
│   ├── models/__tests__/              # Model/interface tests
│   └── setupTests.ts                  # Jest configuration and global test utilities
├── submitImage/
│   ├── __tests__/                     # Go main package tests
│   └── appleauth/__tests__/           # Apple authentication tests
├── jest.config.js                     # Jest configuration
├── test-runner.sh                     # Comprehensive test runner script
└── TESTING.md                         # This file
```

## Prerequisites

- **Node.js** (v14 or higher) for frontend tests
- **Go** (v1.19 or higher) for backend tests
- **npm** or **yarn** for package management

## Running Tests

### Quick Start

```bash
# Make the test runner executable
chmod +x test-runner.sh

# Run all tests
./test-runner.sh

# Run specific test suites
./test-runner.sh frontend    # Frontend tests only
./test-runner.sh backend     # Backend tests only
./test-runner.sh apple       # Apple auth tests only
```

### Frontend Tests

```bash
# Run all frontend tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in CI mode (no watch)
npm run test:ci

# Run tests in watch mode
npm run test:watch

# Run specific test files
npm test -- AppleLoginButton.test.tsx

# Run tests matching a pattern
npm test -- --testPathPattern="components"
```

### Backend Tests

```bash
# Run all Go tests
npm run test:go

# Run Go tests with coverage
npm run test:go-coverage

# Run tests directly with Go
cd submitImage
go test ./... -v

# Run specific package tests
go test ./appleauth/... -v

# Run tests with coverage profile
go test ./... -v -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Linting

```bash
# Run ESLint
npm run lint

# Fix linting issues automatically
npm run lint:fix
```

## Test Categories

### 1. Component Tests

Located in `src/components/__tests__/`

- **AppleLoginButton.test.tsx**: Tests Apple Sign-In button functionality
- **SignatureCanvas.test.tsx**: Tests signature drawing canvas component

**Key Testing Areas:**
- Component rendering
- User interactions (mouse/touch events)
- Props handling
- Error states
- Loading states
- Event callbacks

### 2. Service Tests

Located in `src/services/__tests__/`

- **AppleAuthService.test.ts**: Tests Apple authentication service
- **SignatureService.test.ts**: Tests signature management service

**Key Testing Areas:**
- API calls and responses
- Error handling
- Token validation
- Data transformation
- Service integration

### 3. Model Tests

Located in `src/models/__tests__/`

- **AppleUser.test.ts**: Tests AppleUserBuilder and related interfaces

**Key Testing Areas:**
- Builder pattern implementation
- Data validation
- Type safety
- Edge cases

### 4. Backend Tests

Located in `submitImage/__tests__/` and `submitImage/appleauth/__tests__/`

- **main_test.go**: Tests main router and request handling
- **apple_auth_test.go**: Tests Apple authentication logic (existing)
- **apple_auth_extended_test.go**: Extended Apple auth tests

**Key Testing Areas:**
- HTTP request routing
- Apple JWT token validation
- Authentication flows
- Error handling
- Concurrent access
- Performance benchmarks

## Test Utilities and Helpers

### Frontend Test Utilities

The `setupTests.ts` file provides:

- Global mocks for browser APIs
- Custom Jest matchers
- Test data factories
- Common test utilities

```typescript
// Example usage of test utilities
const mockUser = global.testUtils.createMockAppleUser();
const mockSignature = global.testUtils.createMockSignature();

// Custom matchers
expect(signatureId).toBeValidSignatureId();
expect(user).toBeValidAppleUser();
```

### Backend Test Utilities

Go tests use testify for assertions and mocking:

```go
// Example usage
assert.Equal(t, expected, actual)
require.NoError(t, err)
mock.AssertExpectations(t)
```

## Coverage Requirements

The project maintains high test coverage standards:

### Frontend Coverage Thresholds
- **Branches**: 80%
- **Functions**: 80%
- **Lines**: 80%
- **Statements**: 80%

### Backend Coverage
- Go tests generate coverage reports in HTML format
- Coverage reports are available at `submitImage/coverage.html`

## Continuous Integration

The test suite is designed for CI/CD environments:

```bash
# CI-friendly test command
npm run test:all
```

This command:
1. Runs frontend tests without watch mode
2. Generates coverage reports
3. Runs backend tests with verbose output
4. Exits with appropriate status codes

## Mock Strategy

### Frontend Mocks

- **External APIs**: Mocked using Jest mocks
- **Browser APIs**: Mocked in setupTests.ts
- **Third-party libraries**: Mocked per test file
- **Environment variables**: Mocked in test setup

### Backend Mocks

- **AWS Services**: Mocked using testify/mock
- **HTTP clients**: Mocked with httptest
- **External APIs**: Mocked with test servers

## Test Data Management

### Frontend Test Data

Test data is managed through factory functions:

```typescript
// Create consistent test data
const testUser = global.testUtils.createMockAppleUser();
const testSignature = global.testUtils.createMockSignature();
```

### Backend Test Data

Test data is generated within test functions:

```go
// Generate test RSA keys
privateKey := generateTestPrivateKey(t)

// Create test JWT tokens
token := createTestJWT(claims)
```

## Debugging Tests

### Frontend Test Debugging

```bash
# Run tests with debugging
npm test -- --verbose

# Run specific test with debugging
npm test -- --testNamePattern="should handle successful login"

# Debug in VS Code
# Add breakpoints and use "Debug Jest Tests" configuration
```

### Backend Test Debugging

```bash
# Run tests with verbose output
go test ./... -v

# Run specific test
go test -run TestAppleAuth_TokenValidation ./appleauth/...

# Run with race detection
go test -race ./...
```

## Performance Testing

### Frontend Performance

- Component rendering performance
- Event handler efficiency
- Memory leak detection

### Backend Performance

- Benchmark tests for critical paths
- Concurrent access testing
- Memory usage analysis

```bash
# Run Go benchmarks
go test -bench=. ./...
```

## Best Practices

### Writing Tests

1. **Arrange, Act, Assert**: Structure tests clearly
2. **Descriptive names**: Use clear, descriptive test names
3. **Single responsibility**: Test one thing per test
4. **Mock external dependencies**: Keep tests isolated
5. **Test edge cases**: Include error conditions and edge cases

### Test Organization

1. **Group related tests**: Use describe blocks (Jest) or subtests (Go)
2. **Setup and teardown**: Use beforeEach/afterEach appropriately
3. **Shared utilities**: Extract common test logic
4. **Clear assertions**: Use specific, meaningful assertions

### Maintenance

1. **Keep tests updated**: Update tests when code changes
2. **Remove obsolete tests**: Clean up tests for removed features
3. **Monitor coverage**: Maintain coverage thresholds
4. **Review test failures**: Investigate and fix flaky tests

## Troubleshooting

### Common Issues

1. **Tests timing out**: Increase timeout or fix async handling
2. **Mock not working**: Check mock setup and imports
3. **Coverage not accurate**: Verify file patterns in configuration
4. **Flaky tests**: Identify and fix race conditions

### Getting Help

- Check test output for specific error messages
- Review test configuration files
- Consult framework documentation (Jest, testify)
- Use debugging tools and techniques

## Contributing

When adding new features:

1. Write tests for new functionality
2. Maintain or improve coverage
3. Follow existing test patterns
4. Update this documentation if needed

## Resources

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro/)
- [Go Testing Package](https://golang.org/pkg/testing/)
- [Testify Documentation](https://github.com/stretchr/testify)