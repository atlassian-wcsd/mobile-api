# User Registration Implementation

This document describes the implementation of user registration functionality in the backend API.

## Overview

The user registration system provides secure user account creation with the following features:

- **Unique username validation**: Ensures usernames are unique across the system
- **Email validation**: Validates email format and uniqueness
- **Secure password requirements**: Enforces strong password policies
- **Password confirmation**: Requires users to confirm their password
- **Terms and privacy acceptance**: Ensures users accept legal agreements
- **CAPTCHA verification**: Prevents automated registrations
- **Email verification**: Sends verification emails to confirm email addresses
- **GDPR compliance**: Implements data protection best practices

## API Endpoints

### POST /auth/register

Registers a new user account.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "profilePicture": "https://example.com/avatar.jpg",
  "bio": "Software developer",
  "termsAccepted": true,
  "privacyAccepted": true,
  "captchaToken": "03AGdBq26..."
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account.",
  "userId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (400 Bad Request):**
```json
{
  "success": false,
  "error": "Username already exists"
}
```

### POST /auth/verify-email

Verifies a user's email address using a verification token.

**Request Body:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Email verified successfully. Your account is now active."
}
```

**Response (400 Bad Request):**
```json
{
  "success": false,
  "error": "Invalid or expired verification token"
}
```

## Validation Rules

### Username
- **Length**: 3-30 characters
- **Characters**: Letters, numbers, and underscores only
- **Uniqueness**: Must be unique across all users

### Email
- **Format**: Valid email format (RFC 5322 compliant)
- **Uniqueness**: Must be unique across all users

### Password
- **Minimum length**: 8 characters
- **Complexity requirements**:
  - At least one uppercase letter (A-Z)
  - At least one lowercase letter (a-z)
  - At least one digit (0-9)
  - At least one special character (!@#$%^&*()_+-=[]{}|;':"\\,.<>?)
- **Confirmation**: Must match the confirmPassword field

### Optional Fields
- **First Name**: Maximum 50 characters
- **Last Name**: Maximum 50 characters
- **Bio**: Maximum 500 characters
- **Profile Picture**: Valid URL (optional)

### Required Agreements
- **Terms Accepted**: Must be true
- **Privacy Accepted**: Must be true

## Security Features

### Password Security
- Passwords are hashed using bcrypt with default cost (currently 10)
- Plain text passwords are never stored in the database
- Password hashes are never exposed in API responses

### CAPTCHA Verification
- Google reCAPTCHA integration to prevent automated registrations
- Configurable secret key via environment variables
- Test mode available for development environments

### Email Verification
- Unique verification tokens generated for each user
- Tokens are stored securely and cleared after verification
- Email verification required before account activation

### Data Protection
- Sensitive fields (password hash, verification tokens) are never exposed in API responses
- User data is sanitized before being returned in responses
- Compliance with GDPR data protection requirements

## Database Schema

### Users Table (DynamoDB)

**Primary Key**: `id` (String)

**Global Secondary Indexes**:
- `username-index`: For username uniqueness checks
- `email-index`: For email uniqueness checks

**Attributes**:
```
id: String (UUID)
username: String
email: String
password_hash: String
first_name: String (optional)
last_name: String (optional)
profile_picture: String (optional)
bio: String (optional)
email_verified: Boolean
email_verify_token: String
terms_accepted: Boolean
privacy_accepted: Boolean
created_at: String (ISO 8601)
updated_at: String (ISO 8601)
last_login_at: String (ISO 8601, optional)
is_active: Boolean
```

## Email Templates

### Verification Email
- **Subject**: "Verify Your Email Address"
- **Content**: HTML and plain text versions
- **Includes**: Verification link with token
- **Expiration**: 24 hours (recommended)

### Welcome Email
- **Subject**: "Welcome to Our App!"
- **Content**: Sent after successful email verification
- **Includes**: Getting started information

## Environment Variables

### Required
- `FROM_EMAIL`: Email address for sending emails (must be verified in SES)
- `BASE_URL`: Base URL for email verification links

### Optional
- `RECAPTCHA_SECRET_KEY`: Google reCAPTCHA secret key (defaults to test mode)

## Error Handling

### Validation Errors (400)
- Invalid email format
- Weak password
- Password mismatch
- Username/email already exists
- Missing required fields
- CAPTCHA verification failed

### Server Errors (500)
- Database connection issues
- Email sending failures (non-blocking)
- Internal processing errors

## Testing

### Unit Tests
- Password validation
- Email format validation
- Username validation
- CAPTCHA verification
- Database operations
- Email verification

### Integration Tests
- End-to-end registration flow
- Email verification flow
- Error scenarios

### Test Data
- Mock CAPTCHA tokens for testing
- Test email addresses
- Sample user data

## Deployment

### AWS Services Required
- **Lambda**: For serverless function execution
- **DynamoDB**: For user data storage
- **SES**: For email sending
- **API Gateway**: For HTTP API endpoints

### CloudFormation Template
The `template.yml` file includes:
- Lambda function configuration
- API Gateway endpoints
- DynamoDB table creation
- SES permissions
- Environment variable configuration

### Database Setup
Run the table creation script:
```bash
go run submitImage/scripts/create_tables.go
```

## Monitoring and Logging

### CloudWatch Logs
- Registration attempts
- Validation failures
- Email sending status
- Database operations

### Metrics to Monitor
- Registration success rate
- Email verification rate
- CAPTCHA failure rate
- Response times

## Security Considerations

### Rate Limiting
- Implement rate limiting on registration endpoints
- Monitor for suspicious activity patterns

### Input Sanitization
- All user inputs are validated and sanitized
- SQL injection prevention (not applicable with DynamoDB)
- XSS prevention in stored data

### Data Retention
- Consider implementing data retention policies
- Provide user data deletion capabilities (GDPR compliance)

## Future Enhancements

### Potential Features
- Social media registration (Google, Facebook, etc.)
- Two-factor authentication
- Password reset functionality
- Account deactivation/deletion
- User profile management
- Email preferences management

### Performance Optimizations
- Implement caching for username/email existence checks
- Batch email sending for better performance
- Database query optimization

## Troubleshooting

### Common Issues
1. **Email not received**: Check SES configuration and sender verification
2. **CAPTCHA failures**: Verify reCAPTCHA configuration and keys
3. **Database errors**: Check DynamoDB permissions and table existence
4. **Validation errors**: Review input data format and requirements

### Debug Steps
1. Check CloudWatch logs for detailed error messages
2. Verify environment variables are set correctly
3. Test with known good data
4. Check AWS service status and quotas