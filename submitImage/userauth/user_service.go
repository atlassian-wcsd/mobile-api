package userauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	UsersTableName = "Users"
	DefaultUserRole = "user"
	EmailVerifyTokenExpiry = 24 * time.Hour
	PasswordResetTokenExpiry = 1 * time.Hour
	MaxLoginAttempts = 5
	AccountLockDuration = 30 * time.Minute
)

// UserService handles user registration, authentication, and management
type UserService struct {
	dynamoDB dynamodbiface.DynamoDBAPI
	sesClient sesiface.SESAPI
	fromEmail string
	baseURL   string
}

// NewUserService creates a new user service
func NewUserService(dynamoDB dynamodbiface.DynamoDBAPI, sesClient sesiface.SESAPI, fromEmail, baseURL string) *UserService {
	return &UserService{
		dynamoDB:  dynamoDB,
		sesClient: sesClient,
		fromEmail: fromEmail,
		baseURL:   baseURL,
	}
}

// RegisterUser registers a new user
func (s *UserService) RegisterUser(req *UserRegistrationRequest) (*UserRegistrationResponse, error) {
	// Validate the request
	if validationErrors := req.Validate(); validationErrors != nil {
		return &UserRegistrationResponse{
			Success: false,
			Error:   "Validation failed",
		}, fmt.Errorf("validation errors: %+v", validationErrors.Errors)
	}

	// Check if username already exists
	if exists, err := s.usernameExists(req.Username); err != nil {
		return nil, fmt.Errorf("failed to check username existence: %w", err)
	} else if exists {
		return &UserRegistrationResponse{
			Success: false,
			Error:   "Username already taken",
		}, nil
	}

	// Check if email already exists
	if exists, err := s.emailExists(req.Email); err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	} else if exists {
		return &UserRegistrationResponse{
			Success: false,
			Error:   "Email already registered",
		}, nil
	}

	// Generate user ID
	userID := uuid.New().String()

	// Hash password
	passwordHash, salt, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate email verification token
	emailVerifyToken, err := s.generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate email verification token: %w", err)
	}

	// Create user
	now := time.Now()
	user := &User{
		ID:                userID,
		Username:          req.Username,
		Email:             req.Email,
		PasswordHash:      passwordHash,
		Salt:              salt,
		FullName:          req.FullName,
		PhoneNumber:       req.PhoneNumber,
		Role:              DefaultUserRole,
		EmailVerified:     false,
		EmailVerifyToken:  emailVerifyToken,
		EmailVerifyExpiry: now.Add(EmailVerifyTokenExpiry),
		CreatedAt:         now,
		UpdatedAt:         now,
		IsActive:          true,
		LoginAttempts:     0,
	}

	// Save user to database
	if err := s.saveUser(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Send verification email
	if err := s.sendVerificationEmail(user.Email, user.FullName, emailVerifyToken); err != nil {
		// Log error but don't fail registration
		fmt.Printf("Failed to send verification email to %s: %v\n", user.Email, err)
	}

	return &UserRegistrationResponse{
		Success: true,
		Message: "User registered successfully. Please check your email for verification.",
		UserID:  userID,
	}, nil
}

// VerifyEmail verifies a user's email address
func (s *UserService) VerifyEmail(token string) error {
	user, err := s.getUserByEmailVerifyToken(token)
	if err != nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	// Check if token is expired
	if time.Now().After(user.EmailVerifyExpiry) {
		return fmt.Errorf("verification token has expired")
	}

	// Update user
	user.EmailVerified = true
	user.EmailVerifyToken = ""
	user.UpdatedAt = time.Now()

	if err := s.updateUser(user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// LoginUser authenticates a user and returns tokens
func (s *UserService) LoginUser(req *UserLoginRequest) (*UserLoginResponse, error) {
	// Get user by username or email
	user, err := s.getUserByUsernameOrEmail(req.Username)
	if err != nil {
		return &UserLoginResponse{
			Success: false,
			Error:   "Invalid username or password",
		}, nil
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return &UserLoginResponse{
			Success: false,
			Error:   "Account is temporarily locked due to too many failed login attempts",
		}, nil
	}

	// Check if account is active
	if !user.IsActive {
		return &UserLoginResponse{
			Success: false,
			Error:   "Account is deactivated",
		}, nil
	}

	// Verify password
	if !s.verifyPassword(req.Password, user.PasswordHash, user.Salt) {
		// Increment login attempts
		user.LoginAttempts++
		if user.LoginAttempts >= MaxLoginAttempts {
			lockUntil := time.Now().Add(AccountLockDuration)
			user.LockedUntil = &lockUntil
		}
		user.UpdatedAt = time.Now()
		s.updateUser(user) // Ignore error for security reasons

		return &UserLoginResponse{
			Success: false,
			Error:   "Invalid username or password",
		}, nil
	}

	// Reset login attempts on successful login
	user.LoginAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	user.UpdatedAt = now

	if err := s.updateUser(user); err != nil {
		return nil, fmt.Errorf("failed to update user login info: %w", err)
	}

	// Generate tokens (simplified - in production use proper JWT)
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &UserLoginResponse{
		Success:      true,
		Message:      "Login successful",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user.ToPublicUser(),
	}, nil
}

// RequestPasswordReset initiates a password reset process
func (s *UserService) RequestPasswordReset(email string) error {
	user, err := s.getUserByEmail(email)
	if err != nil {
		// Don't reveal if email exists for security reasons
		return nil
	}

	// Generate password reset token
	resetToken, err := s.generateSecureToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Update user with reset token
	user.PasswordResetToken = resetToken
	user.PasswordResetExpiry = time.Now().Add(PasswordResetTokenExpiry)
	user.UpdatedAt = time.Now()

	if err := s.updateUser(user); err != nil {
		return fmt.Errorf("failed to update user with reset token: %w", err)
	}

	// Send password reset email
	if err := s.sendPasswordResetEmail(user.Email, user.FullName, resetToken); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

// ResetPassword resets a user's password using a reset token
func (s *UserService) ResetPassword(token, newPassword string) error {
	// Validate new password
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	user, err := s.getUserByPasswordResetToken(token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token is expired
	if time.Now().After(user.PasswordResetExpiry) {
		return fmt.Errorf("reset token has expired")
	}

	// Hash new password
	passwordHash, salt, err := s.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update user
	user.PasswordHash = passwordHash
	user.Salt = salt
	user.PasswordResetToken = ""
	user.LoginAttempts = 0
	user.LockedUntil = nil
	user.UpdatedAt = time.Now()

	if err := s.updateUser(user); err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	return nil
}

// hashPassword hashes a password with a random salt using bcrypt
func (s *UserService) hashPassword(password string) (string, string, error) {
	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	saltStr := base64.StdEncoding.EncodeToString(salt)

	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return string(hashedPassword), saltStr, nil
}

// verifyPassword verifies a password against its hash and salt
func (s *UserService) verifyPassword(password, hash, salt string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+salt))
	return err == nil
}

// generateSecureToken generates a cryptographically secure random token
func (s *UserService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateAccessToken generates an access token for the user (simplified)
func (s *UserService) generateAccessToken(user *User) (string, error) {
	// In production, use proper JWT with signing
	tokenData := fmt.Sprintf("%s:%s:%d", user.ID, user.Username, time.Now().Unix())
	hash := sha256.Sum256([]byte(tokenData))
	return base64.URLEncoding.EncodeToString(hash[:]), nil
}

// generateRefreshToken generates a refresh token for the user
func (s *UserService) generateRefreshToken(user *User) (string, error) {
	return s.generateSecureToken()
}

// Database operations

// usernameExists checks if a username already exists
func (s *UserService) usernameExists(username string) (bool, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(UsersTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"username": {
				S: aws.String(username),
			},
		},
	}

	result, err := s.dynamoDB.GetItem(input)
	if err != nil {
		return false, err
	}

	return len(result.Item) > 0, nil
}

// emailExists checks if an email already exists
func (s *UserService) emailExists(email string) (bool, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(UsersTableName),
		IndexName:              aws.String("EmailIndex"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}

	result, err := s.dynamoDB.Query(input)
	if err != nil {
		return false, err
	}

	return *result.Count > 0, nil
}

// saveUser saves a user to the database
func (s *UserService) saveUser(user *User) error {
	item := map[string]*dynamodb.AttributeValue{
		"id":                    {S: aws.String(user.ID)},
		"username":              {S: aws.String(user.Username)},
		"email":                 {S: aws.String(user.Email)},
		"password_hash":         {S: aws.String(user.PasswordHash)},
		"salt":                  {S: aws.String(user.Salt)},
		"role":                  {S: aws.String(user.Role)},
		"email_verified":        {BOOL: aws.Bool(user.EmailVerified)},
		"email_verify_token":    {S: aws.String(user.EmailVerifyToken)},
		"email_verify_expiry":   {S: aws.String(user.EmailVerifyExpiry.Format(time.RFC3339))},
		"created_at":            {S: aws.String(user.CreatedAt.Format(time.RFC3339))},
		"updated_at":            {S: aws.String(user.UpdatedAt.Format(time.RFC3339))},
		"is_active":             {BOOL: aws.Bool(user.IsActive)},
		"login_attempts":        {N: aws.String(fmt.Sprintf("%d", user.LoginAttempts))},
	}

	if user.FullName != "" {
		item["full_name"] = &dynamodb.AttributeValue{S: aws.String(user.FullName)}
	}
	if user.PhoneNumber != "" {
		item["phone_number"] = &dynamodb.AttributeValue{S: aws.String(user.PhoneNumber)}
	}
	if user.LastLoginAt != nil {
		item["last_login_at"] = &dynamodb.AttributeValue{S: aws.String(user.LastLoginAt.Format(time.RFC3339))}
	}
	if user.LockedUntil != nil {
		item["locked_until"] = &dynamodb.AttributeValue{S: aws.String(user.LockedUntil.Format(time.RFC3339))}
	}
	if user.PasswordResetToken != "" {
		item["password_reset_token"] = &dynamodb.AttributeValue{S: aws.String(user.PasswordResetToken)}
		item["password_reset_expiry"] = &dynamodb.AttributeValue{S: aws.String(user.PasswordResetExpiry.Format(time.RFC3339))}
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(UsersTableName),
		Item:      item,
	}

	_, err := s.dynamoDB.PutItem(input)
	return err
}

// updateUser updates a user in the database
func (s *UserService) updateUser(user *User) error {
	return s.saveUser(user) // For simplicity, using put operation
}

// getUserByUsernameOrEmail retrieves a user by username or email
func (s *UserService) getUserByUsernameOrEmail(usernameOrEmail string) (*User, error) {
	// Try username first
	if user, err := s.getUserByUsername(usernameOrEmail); err == nil {
		return user, nil
	}

	// Try email
	return s.getUserByEmail(usernameOrEmail)
}

// getUserByUsername retrieves a user by username
func (s *UserService) getUserByUsername(username string) (*User, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(UsersTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"username": {
				S: aws.String(username),
			},
		},
	}

	result, err := s.dynamoDB.GetItem(input)
	if err != nil {
		return nil, err
	}

	if len(result.Item) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return s.itemToUser(result.Item)
}

// getUserByEmail retrieves a user by email
func (s *UserService) getUserByEmail(email string) (*User, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(UsersTableName),
		IndexName:              aws.String("EmailIndex"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {
				S: aws.String(email),
			},
		},
	}

	result, err := s.dynamoDB.Query(input)
	if err != nil {
		return nil, err
	}

	if *result.Count == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return s.itemToUser(result.Items[0])
}

// getUserByEmailVerifyToken retrieves a user by email verification token
func (s *UserService) getUserByEmailVerifyToken(token string) (*User, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(UsersTableName),
		IndexName:              aws.String("EmailVerifyTokenIndex"),
		KeyConditionExpression: aws.String("email_verify_token = :token"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
		},
	}

	result, err := s.dynamoDB.Query(input)
	if err != nil {
		return nil, err
	}

	if *result.Count == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return s.itemToUser(result.Items[0])
}

// getUserByPasswordResetToken retrieves a user by password reset token
func (s *UserService) getUserByPasswordResetToken(token string) (*User, error) {
	input := &dynamodb.QueryInput{
		TableName:              aws.String(UsersTableName),
		IndexName:              aws.String("PasswordResetTokenIndex"),
		KeyConditionExpression: aws.String("password_reset_token = :token"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":token": {
				S: aws.String(token),
			},
		},
	}

	result, err := s.dynamoDB.Query(input)
	if err != nil {
		return nil, err
	}

	if *result.Count == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return s.itemToUser(result.Items[0])
}

// itemToUser converts a DynamoDB item to a User struct
func (s *UserService) itemToUser(item map[string]*dynamodb.AttributeValue) (*User, error) {
	user := &User{}

	if v, ok := item["id"]; ok && v.S != nil {
		user.ID = *v.S
	}
	if v, ok := item["username"]; ok && v.S != nil {
		user.Username = *v.S
	}
	if v, ok := item["email"]; ok && v.S != nil {
		user.Email = *v.S
	}
	if v, ok := item["password_hash"]; ok && v.S != nil {
		user.PasswordHash = *v.S
	}
	if v, ok := item["salt"]; ok && v.S != nil {
		user.Salt = *v.S
	}
	if v, ok := item["full_name"]; ok && v.S != nil {
		user.FullName = *v.S
	}
	if v, ok := item["phone_number"]; ok && v.S != nil {
		user.PhoneNumber = *v.S
	}
	if v, ok := item["role"]; ok && v.S != nil {
		user.Role = *v.S
	}
	if v, ok := item["email_verified"]; ok && v.BOOL != nil {
		user.EmailVerified = *v.BOOL
	}
	if v, ok := item["email_verify_token"]; ok && v.S != nil {
		user.EmailVerifyToken = *v.S
	}
	if v, ok := item["email_verify_expiry"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.EmailVerifyExpiry = t
		}
	}
	if v, ok := item["password_reset_token"]; ok && v.S != nil {
		user.PasswordResetToken = *v.S
	}
	if v, ok := item["password_reset_expiry"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.PasswordResetExpiry = t
		}
	}
	if v, ok := item["created_at"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.CreatedAt = t
		}
	}
	if v, ok := item["updated_at"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.UpdatedAt = t
		}
	}
	if v, ok := item["last_login_at"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.LastLoginAt = &t
		}
	}
	if v, ok := item["is_active"]; ok && v.BOOL != nil {
		user.IsActive = *v.BOOL
	}
	if v, ok := item["login_attempts"]; ok && v.N != nil {
		if attempts, err := fmt.Sscanf(*v.N, "%d", &user.LoginAttempts); err != nil || attempts != 1 {
			user.LoginAttempts = 0
		}
	}
	if v, ok := item["locked_until"]; ok && v.S != nil {
		if t, err := time.Parse(time.RFC3339, *v.S); err == nil {
			user.LockedUntil = &t
		}
	}

	return user, nil
}

// Email operations

// sendVerificationEmail sends an email verification email
func (s *UserService) sendVerificationEmail(email, fullName, token string) error {
	if s.sesClient == nil {
		return fmt.Errorf("SES client not configured")
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)
	
	subject := "Verify Your Email Address"
	htmlBody := fmt.Sprintf(`
		<html>
		<body>
			<h2>Welcome to Our Platform!</h2>
			<p>Hi %s,</p>
			<p>Thank you for registering with us. Please click the link below to verify your email address:</p>
			<p><a href="%s">Verify Email Address</a></p>
			<p>This link will expire in 24 hours.</p>
			<p>If you didn't create an account, please ignore this email.</p>
		</body>
		</html>
	`, fullName, verifyURL)

	textBody := fmt.Sprintf(`
		Welcome to Our Platform!
		
		Hi %s,
		
		Thank you for registering with us. Please visit the following link to verify your email address:
		
		%s
		
		This link will expire in 24 hours.
		
		If you didn't create an account, please ignore this email.
	`, fullName, verifyURL)

	input := &ses.SendEmailInput{
		Source: aws.String(s.fromEmail),
		Destination: &ses.Destination{
			ToAddresses: []*string{aws.String(email)},
		},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: aws.String(subject),
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Data: aws.String(htmlBody),
				},
				Text: &ses.Content{
					Data: aws.String(textBody),
				},
			},
		},
	}

	_, err := s.sesClient.SendEmail(input)
	return err
}

// sendPasswordResetEmail sends a password reset email
func (s *UserService) sendPasswordResetEmail(email, fullName, token string) error {
	if s.sesClient == nil {
		return fmt.Errorf("SES client not configured")
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, token)
	
	subject := "Password Reset Request"
	htmlBody := fmt.Sprintf(`
		<html>
		<body>
			<h2>Password Reset Request</h2>
			<p>Hi %s,</p>
			<p>We received a request to reset your password. Click the link below to reset it:</p>
			<p><a href="%s">Reset Password</a></p>
			<p>This link will expire in 1 hour.</p>
			<p>If you didn't request a password reset, please ignore this email.</p>
		</body>
		</html>
	`, fullName, resetURL)

	textBody := fmt.Sprintf(`
		Password Reset Request
		
		Hi %s,
		
		We received a request to reset your password. Visit the following link to reset it:
		
		%s
		
		This link will expire in 1 hour.
		
		If you didn't request a password reset, please ignore this email.
	`, fullName, resetURL)

	input := &ses.SendEmailInput{
		Source: aws.String(s.fromEmail),
		Destination: &ses.Destination{
			ToAddresses: []*string{aws.String(email)},
		},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: aws.String(subject),
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Data: aws.String(htmlBody),
				},
				Text: &ses.Content{
					Data: aws.String(textBody),
				},
			},
		},
	}

	_, err := s.sesClient.SendEmail(input)
	return err
}