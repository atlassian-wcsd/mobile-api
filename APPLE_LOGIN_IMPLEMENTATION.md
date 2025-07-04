# Apple Login Implementation Guide

This document provides a comprehensive guide for implementing Apple Login authentication in the Mobile Dev project (MOBL-2555).

## 📋 Overview

The implementation includes:
- **Frontend**: React/TypeScript components for Apple Login UI
- **Backend**: Go-based Lambda functions for Apple ID token verification
- **API**: RESTful endpoints for authentication operations
- **Infrastructure**: AWS SAM template with proper routing

## 🏗️ Architecture

```
Frontend (React/TypeScript)
├── AppleLoginButton.tsx - UI component for Apple Login
├── AppleAuthService.ts - Service for API communication
└── AppleUser.ts - User data models

Backend (Go/Lambda)
├── appleauth/apple_auth.go - Core Apple authentication logic
├── appleauth/apple_auth_test.go - Unit tests
└── opendevopslambda/apple_auth_handler.go - HTTP handlers

Infrastructure
├── template.yml - SAM template with Apple auth endpoints
└── api.yaml - OpenAPI specification
```

## 🚀 Implementation Steps

### 1. Frontend Integration

#### Add Apple Login Button to your app:

```tsx
import { AppleLoginButton } from './components/AppleLoginButton';
import { AppleUser } from './models/AppleUser';

function LoginPage() {
  const handleAppleSuccess = (user: AppleUser) => {
    console.log('Apple login successful:', user);
    // Store user data, redirect, etc.
  };

  const handleAppleError = (error: string) => {
    console.error('Apple login failed:', error);
    // Show error message to user
  };

  return (
    <div>
      <AppleLoginButton
        onSuccess={handleAppleSuccess}
        onError={handleAppleError}
      />
    </div>
  );
}
```

#### Add Apple ID SDK to your HTML:

```html
<script type="text/javascript" src="https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js"></script>
```

#### Set environment variables:

```bash
REACT_APP_APPLE_CLIENT_ID=your.app.bundle.id
REACT_APP_APPLE_REDIRECT_URI=https://yourapp.com/auth/callback
REACT_APP_API_BASE_URL=https://your-api-gateway-url.com
```

### 2. Backend Configuration

#### Set up Apple Developer Account:

1. **Create App ID** in Apple Developer Console
2. **Enable Sign in with Apple** capability
3. **Create Service ID** for web authentication
4. **Generate Private Key** for server-to-server communication
5. **Configure domains and redirect URLs**

#### Set environment variables for Lambda:

```bash
APPLE_CLIENT_ID=your.service.id
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_KEY_ID=YOUR_KEY_ID
APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

### 3. Deploy Infrastructure

#### Deploy with SAM:

```bash
# Build the application
sam build

# Deploy with Apple configuration
sam deploy --parameter-overrides \
  AppleClientId=your.service.id \
  AppleTeamId=YOUR_TEAM_ID \
  AppleKeyId=YOUR_KEY_ID \
  ApplePrivateKey="$(cat AppleAuthKey.p8)"
```

## 🔧 API Endpoints

### POST /auth/apple/verify
Verifies Apple ID token and returns user information.

**Request:**
```json
{
  "identityToken": "eyJ...",
  "authorizationCode": "c123...",
  "user": {
    "name": {
      "firstName": "John",
      "lastName": "Doe"
    },
    "email": "john.doe@example.com"
  }
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": "001234.567890abcdef",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "fullName": "John Doe",
    "isPrivateEmail": false,
    "authToken": "eyJ...",
    "expiresAt": "2024-01-01T12:00:00Z",
    "createdAt": "2024-01-01T10:00:00Z",
    "lastLoginAt": "2024-01-01T10:00:00Z"
  }
}
```

### POST /auth/apple/refresh
Refreshes authentication token using refresh token.

### POST /auth/apple/signout
Signs out user and revokes tokens.

### GET /auth/apple/profile
Gets current user profile (requires Bearer token).

## 🧪 Testing

### Run Backend Tests:

```bash
cd submitImage
go test ./appleauth -v
go test ./opendevopslambda -v
```

### Test API Endpoints:

```bash
# Test token verification
curl -X POST https://your-api.com/auth/apple/verify \
  -H "Content-Type: application/json" \
  -d '{"identityToken": "test_token"}'

# Test profile endpoint
curl -X GET https://your-api.com/auth/apple/profile \
  -H "Authorization: Bearer your_token"
```

## 🔒 Security Considerations

### Token Validation:
- ✅ Verify token signature using Apple's public keys
- ✅ Validate issuer (`https://appleid.apple.com`)
- ✅ Validate audience (your client ID)
- ✅ Check token expiration
- ✅ Validate issued-at time

### Best Practices:
- 🔐 Store Apple private key securely (AWS Secrets Manager recommended)
- 🔄 Implement token refresh logic
- 📝 Log authentication events for audit
- 🚫 Implement rate limiting
- 🛡️ Use HTTPS for all communications
- 🔒 Implement proper CORS policies

## 📚 Dependencies

### Frontend:
```json
{
  "dependencies": {
    "react": "^18.0.0",
    "typescript": "^4.0.0"
  }
}
```

### Backend:
```go
module submit-image

require (
    github.com/aws/aws-lambda-go v1.34.1
    github.com/aws/aws-sdk-go v1.44.0
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/stretchr/testify v1.8.0
)
```

## 🐛 Troubleshooting

### Common Issues:

1. **"Invalid client_id"**
   - Verify APPLE_CLIENT_ID matches your Service ID
   - Check domain configuration in Apple Developer Console

2. **"Invalid token signature"**
   - Ensure Apple's public keys are fetched correctly
   - Verify token parsing logic

3. **"Token expired"**
   - Implement proper token refresh logic
   - Check system clock synchronization

4. **CORS errors**
   - Verify CORS headers in API responses
   - Check allowed origins configuration

### Debug Mode:
Enable debug logging by setting:
```bash
LOG_LEVEL=debug
```

## 📖 Additional Resources

- [Apple Sign In Documentation](https://developer.apple.com/sign-in-with-apple/)
- [Apple ID Token Validation](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_a_user)
- [JWT Token Handling](https://jwt.io/)
- [AWS Lambda Go Documentation](https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html)

## ✅ Acceptance Criteria Checklist

Based on MOBL-2520 acceptance criteria:

### Functional Requirements:
- [ ] System supports Apple Login as authentication option
- [ ] Users can log in using Apple ID credentials
- [ ] Login process is seamless and intuitive
- [ ] Login interface is consistent with existing UI/UX
- [ ] Clear instructions and feedback during login

### Security & Privacy:
- [ ] Adheres to Apple's guidelines and best practices
- [ ] Prevents unauthorized access
- [ ] Ensures secure data transmission

### Performance:
- [ ] Quick and responsive login process
- [ ] Compatible with latest iOS versions
- [ ] Handles concurrent login requests

### Technical Implementation:
- [ ] Updated LoginHandler with Apple Login endpoint
- [ ] Enhanced AuthService with Apple ID token verification
- [ ] Updated LoginLogger for Apple Login attempts

## 🎯 Next Steps

1. **Complete Implementation**: Finish the JWK to RSA conversion in `apple_auth.go`
2. **Add Database Integration**: Store user data in your database
3. **Implement Session Management**: Create user sessions after authentication
4. **Add Monitoring**: Implement CloudWatch metrics and alarms
5. **Security Hardening**: Move secrets to AWS Secrets Manager
6. **Load Testing**: Test with concurrent users
7. **Documentation**: Update API documentation with examples