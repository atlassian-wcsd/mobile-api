# User Registration Backend Implementation

## Overview

This document describes the comprehensive user registration backend system implemented for the application. The system provides secure user registration, authentication, email verification, password reset, and account management functionality.

## Features Implemented

### 1. User Data Collection
- **Username**: 3-20 characters, alphanumeric with underscores and hyphens
- **Password**: Minimum 8 characters with complexity requirements
- **Email**: Valid email format, unique within the system
- **Full Name**: Optional, up to 100 characters
- **Phone Number**: Optional, 10-15 digits with flexible formatting

### 2. Validation Rules
- **Username Validation**:
  - Length: 3-20 characters
  - Characters: Letters, numbers, underscores, hyphens only
  - Cannot start or end with underscore or hyphen
  - Must be unique in the system

- **Password Validation**:
  - Minimum 8 characters
  - Must contain at least one uppercase letter
  - Must contain at least one lowercase letter
  - Must contain at least one number
  - Must contain at least one special character

- **Email Validation**:
  - Valid email format using regex
  - Maximum 254 characters
  - Must be unique in the system

### 3. Security Measures
- **Password Hashing**: Uses bcrypt with random salt for each password
- **Rate Limiting**: Prevents brute-force attacks with configurable limits
- **Account Locking**: Temporary account lock after failed login attempts
- **Secure Tokens**: Cryptographically secure random tokens for verification
- **HTTPS**: All endpoints support HTTPS (configured at infrastructure level)

### 4. Email Verification
- Automatic verification email sent upon registration
- 24-hour expiration for verification tokens
- HTML and text email formats supported
- Configurable email templates

### 5. Password Recovery
- Password reset via email
- 1-hour expiration for reset tokens
- Secure token generation
- Password complexity validation for new passwords

### 6. Rate Limiting
- Registration: 3 attempts per 15 minutes per IP
- Login: 5 attempts per 5 minutes per IP
- Password Reset: 3 attempts per hour per IP
- Automatic cleanup of expired rate limit entries

### 7. User Role Management
- Default role assignment ("user")
- Support for multiple roles (user, admin, moderator)
- Role-based access control ready

## API Endpoints

### POST /api/register
Registers a new user account.

**Request Body:**
```json
{
  "username": "testuser",
  "password": "SecurePass123!",
  "email": "user@example.com",
  "fullName": "Test User",
  "phoneNumber": "1234567890"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for verification.",
  "userId": "uuid-here"
}
```

### POST /api/login
Authenticates a user and returns tokens.

**Request Body:**
```json
{
  "username": "testuser",
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "accessToken": "token-here",
  "refreshToken": "refresh-token-here",
  "user": {
    "id": "uuid-here",
    "username": "testuser",
    "email": "user@example.com",
    "fullName": "Test User",
    "role": "user",
    "emailVerified": true,
    "isActive": true,
    "createdAt": "2023-01-01T00:00:00Z",
    "updatedAt": "2023-01-01T00:00:00Z"
  }
}
```

### POST /api/verify-email
Verifies a user's email address.

**Request Body:**
```json
{
  "token": "verification-token-here"
}
```

### POST /api/password-reset
Initiates password reset process.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

### POST /api/password-reset-confirm
Confirms password reset with new password.

**Request Body:**
```json
{
  "token": "reset-token-here",
  "newPassword": "NewSecurePass123!"
}
```

## Database Schema

### Users Table (DynamoDB)
- **Primary Key**: `username` (String)
- **Attributes**:
  - `id`: Unique user identifier (UUID)
  - `email`: User's email address
  - `password_hash`: Bcrypt hashed password
  - `salt`: Random salt for password hashing
  - `full_name`: User's full name (optional)
  - `phone_number`: User's phone number (optional)
  - `role`: User's role (default: "user")
  - `email_verified`: Boolean flag for email verification
  - `email_verify_token`: Token for email verification
  - `email_verify_expiry`: Expiration time for verification token
  - `password_reset_token`: Token for password reset
  - `password_reset_expiry`: Expiration time for reset token
  - `created_at`: Account creation timestamp
  - `updated_at`: Last update timestamp
  - `last_login_at`: Last login timestamp
  - `is_active`: Account active status
  - `login_attempts`: Failed login attempt counter
  - `locked_until`: Account lock expiration time

**Global Secondary Indexes**:
- `EmailIndex`: Query by email address
- `EmailVerifyTokenIndex`: Query by email verification token
- `PasswordResetTokenIndex`: Query by password reset token

### RateLimits Table (DynamoDB)
- **Primary Key**: `key` (String) - Format: "endpoint:ip_address"
- **Attributes**:
  - `count`: Number of requests in current window
  - `window_start`: Start time of current rate limit window
  - `expires_at`: TTL for automatic cleanup

## Error Handling

### Validation Errors (400 Bad Request)
```json
{
  "success": false,
  "error": "Validation failed",
  "details": [
    {
      "field": "password",
      "message": "Password must contain at least one uppercase letter"
    }
  ]
}
```

### Rate Limit Errors (429 Too Many Requests)
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "remaining": 0,
  "resetTime": "300s"
}
```

### Authentication Errors (401 Unauthorized)
```json
{
  "success": false,
  "error": "Invalid username or password"
}
```

## Logging and Monitoring

### Registration Events
- Successful registrations with username and user ID
- Failed registrations with reason (without sensitive data)
- Email verification attempts
- Rate limit violations

### Authentication Events
- Successful logins with username
- Failed login attempts with username (without password)
- Account lockouts
- Password reset requests

### Security Events
- Multiple failed login attempts
- Suspicious activity patterns
- Token usage and expiration

## Configuration

### Environment Variables
- `FROM_EMAIL`: Email address for sending notifications (must be verified in SES)
- `BASE_URL`: Base URL for email verification and password reset links
- `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, etc.: Apple authentication configuration

### Rate Limiting Configuration
Rate limits are configurable per endpoint:
- Registration: 3 attempts per 15 minutes
- Login: 5 attempts per 5 minutes
- Password Reset: 3 attempts per hour

### Email Configuration
- Uses AWS SES for email delivery
- Supports both HTML and text email formats
- Configurable email templates
- Automatic retry and error handling

## Security Considerations

### Password Security
- Bcrypt hashing with random salts
- Minimum complexity requirements enforced
- No password storage in logs or responses

### Token Security
- Cryptographically secure random token generation
- Time-limited tokens with automatic expiration
- Secure token transmission via HTTPS

### Account Security
- Account locking after failed attempts
- Email verification required for account activation
- Secure password reset process

### Data Privacy
- Sensitive data never exposed in API responses
- Secure data transmission via HTTPS
- Compliance-ready data handling

## Deployment

### AWS Resources Required
- **Lambda Function**: Main application handler
- **DynamoDB Tables**: Users and RateLimits tables
- **SES**: Email service for notifications
- **API Gateway**: REST API endpoints
- **IAM Roles**: Appropriate permissions for services

### CloudFormation Template
The `template.yml` file includes all necessary AWS resources:
- DynamoDB tables with appropriate indexes
- Lambda function with required permissions
- API Gateway endpoints
- Environment variable configuration

## Testing

### Unit Tests
Comprehensive test suite covering:
- Input validation functions
- Password hashing and verification
- Token generation
- User model methods
- Error handling scenarios

### Integration Tests
- End-to-end registration flow
- Email verification process
- Password reset workflow
- Rate limiting functionality

## Future Enhancements

### Planned Features
- OAuth integration (Google, Facebook, etc.)
- Two-factor authentication (2FA)
- Advanced user profile management
- Audit logging and compliance reporting
- Advanced rate limiting with IP whitelisting

### Scalability Considerations
- Database sharding strategies
- Caching layer implementation
- Microservices architecture migration
- Load balancing and auto-scaling

## Troubleshooting

### Common Issues
1. **Email not received**: Check SES configuration and email verification
2. **Rate limit errors**: Verify IP address extraction and rate limit configuration
3. **Token expiration**: Check system time synchronization
4. **Database errors**: Verify DynamoDB table configuration and permissions

### Monitoring
- CloudWatch metrics for API performance
- DynamoDB metrics for database performance
- SES metrics for email delivery
- Custom metrics for business logic monitoring