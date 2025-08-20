# User Registration System Test Examples

## Example API Calls

### 1. User Registration

**Request:**
```bash
curl -X POST https://your-api-gateway-url/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "SecurePass123!",
    "email": "john.doe@example.com",
    "fullName": "John Doe",
    "phoneNumber": "1234567890"
  }'
```

**Expected Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for verification.",
  "userId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 2. Email Verification

**Request:**
```bash
curl -X POST https://your-api-gateway-url/api/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
  }'
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

### 3. User Login

**Request:**
```bash
curl -X POST https://your-api-gateway-url/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "SecurePass123!"
  }'
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "def456...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe",
    "email": "john.doe@example.com",
    "fullName": "John Doe",
    "phoneNumber": "1234567890",
    "role": "user",
    "emailVerified": true,
    "isActive": true,
    "createdAt": "2023-12-01T10:00:00Z",
    "updatedAt": "2023-12-01T10:00:00Z",
    "lastLoginAt": "2023-12-01T10:30:00Z"
  }
}
```

### 4. Password Reset Request

**Request:**
```bash
curl -X POST https://your-api-gateway-url/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"
  }'
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "If the email exists, a password reset link has been sent"
}
```

### 5. Password Reset Confirmation

**Request:**
```bash
curl -X POST https://your-api-gateway-url/api/password-reset-confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-here",
    "newPassword": "NewSecurePass456!"
  }'
```

**Expected Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

## Error Examples

### 1. Validation Error (400 Bad Request)

**Request with invalid data:**
```bash
curl -X POST https://your-api-gateway-url/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "ab",
    "password": "weak",
    "email": "invalid-email"
  }'
```

**Response:**
```json
{
  "success": false,
  "error": "Validation failed"
}
```

### 2. Rate Limit Error (429 Too Many Requests)

**Response after exceeding rate limit:**
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "remaining": 0,
  "resetTime": "300s"
}
```

### 3. Authentication Error (401 Unauthorized)

**Request with wrong credentials:**
```bash
curl -X POST https://your-api-gateway-url/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "wrongpassword"
  }'
```

**Response:**
```json
{
  "success": false,
  "error": "Invalid username or password"
}
```

## Email Templates

### Registration Verification Email

**Subject:** Verify Your Email Address

**HTML Body:**
```html
<html>
<body>
  <h2>Welcome to Our Platform!</h2>
  <p>Hi John Doe,</p>
  <p>Thank you for registering with us. Please click the link below to verify your email address:</p>
  <p><a href="https://yourapp.com/verify-email?token=abc123...">Verify Email Address</a></p>
  <p>This link will expire in 24 hours.</p>
  <p>If you didn't create an account, please ignore this email.</p>
</body>
</html>
```

### Password Reset Email

**Subject:** Password Reset Request

**HTML Body:**
```html
<html>
<body>
  <h2>Password Reset Request</h2>
  <p>Hi John Doe,</p>
  <p>We received a request to reset your password. Click the link below to reset it:</p>
  <p><a href="https://yourapp.com/reset-password?token=def456...">Reset Password</a></p>
  <p>This link will expire in 1 hour.</p>
  <p>If you didn't request a password reset, please ignore this email.</p>
</body>
</html>
```

## Testing Scenarios

### 1. Complete Registration Flow
1. Register new user → Success
2. Verify email → Success
3. Login with verified account → Success

### 2. Validation Testing
1. Register with short username → Validation error
2. Register with weak password → Validation error
3. Register with invalid email → Validation error
4. Register with existing username → Conflict error
5. Register with existing email → Conflict error

### 3. Rate Limiting Testing
1. Make 3 registration attempts quickly → Success for first 3
2. Make 4th registration attempt → Rate limit error
3. Wait 15 minutes → Rate limit reset
4. Make registration attempt → Success

### 4. Security Testing
1. Login with wrong password 5 times → Account locked
2. Wait 30 minutes → Account unlocked
3. Login with correct password → Success

### 5. Password Reset Flow
1. Request password reset → Success
2. Use reset token to change password → Success
3. Login with new password → Success
4. Try to use same reset token again → Error (token expired/used)

## Deployment Checklist

### AWS Configuration
- [ ] DynamoDB tables created (Users, RateLimits)
- [ ] SES email address verified
- [ ] Lambda function deployed
- [ ] API Gateway endpoints configured
- [ ] Environment variables set (FROM_EMAIL, BASE_URL)
- [ ] IAM permissions configured

### Testing
- [ ] Registration endpoint working
- [ ] Email verification working
- [ ] Login endpoint working
- [ ] Password reset working
- [ ] Rate limiting working
- [ ] Error handling working
- [ ] Email delivery working

### Security
- [ ] HTTPS enabled
- [ ] Rate limiting configured
- [ ] Password complexity enforced
- [ ] Sensitive data not logged
- [ ] Tokens properly secured
- [ ] Account locking working

### Monitoring
- [ ] CloudWatch logs configured
- [ ] Metrics and alarms set up
- [ ] Error tracking enabled
- [ ] Performance monitoring active