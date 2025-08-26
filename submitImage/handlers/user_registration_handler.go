package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"submit-image/models"
	"submit-image/repository"
	"submit-image/services"
	
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
)

// UserRegistrationHandler handles user registration operations
type UserRegistrationHandler struct {
	userRepo       *repository.UserRepository
	emailService   *services.EmailService
	captchaService *services.CaptchaService
}

// NewUserRegistrationHandler creates a new user registration handler
func NewUserRegistrationHandler(dynamoDB dynamodbiface.DynamoDBAPI, sesClient sesiface.SESAPI) *UserRegistrationHandler {
	return &UserRegistrationHandler{
		userRepo:       repository.NewUserRepository(dynamoDB),
		emailService:   services.NewEmailService(sesClient),
		captchaService: services.NewCaptchaService(),
	}
}

// HandleRegister handles user registration requests
func (h *UserRegistrationHandler) HandleRegister(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling user registration request")
	
	// Parse request body
	var regReq models.UserRegistrationRequest
	err := json.Unmarshal([]byte(request.Body), &regReq)
	if err != nil {
		log.Printf("Failed to parse registration request: %v", err)
		return h.errorResponse(400, "Invalid request body"), nil
	}
	
	// Validate input
	if err := h.validateRegistrationRequest(&regReq); err != nil {
		log.Printf("Registration validation failed: %v", err)
		return h.errorResponse(400, err.Error()), nil
	}
	
	// Verify CAPTCHA
	clientIP := services.GetClientIP(request.Headers)
	if err := h.captchaService.VerifyCaptcha(regReq.CaptchaToken, clientIP); err != nil {
		log.Printf("CAPTCHA verification failed: %v", err)
		return h.errorResponse(400, "CAPTCHA verification failed"), nil
	}
	
	// Check if username already exists
	usernameExists, err := h.userRepo.CheckUsernameExists(regReq.Username)
	if err != nil {
		log.Printf("Failed to check username existence: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	if usernameExists {
		return h.errorResponse(400, "Username already exists"), nil
	}
	
	// Check if email already exists
	emailExists, err := h.userRepo.CheckEmailExists(regReq.Email)
	if err != nil {
		log.Printf("Failed to check email existence: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	if emailExists {
		return h.errorResponse(400, "Email already registered"), nil
	}
	
	// Create user model
	user := &models.User{
		Username:        regReq.Username,
		Email:           regReq.Email,
		FirstName:       regReq.FirstName,
		LastName:        regReq.LastName,
		ProfilePicture:  regReq.ProfilePicture,
		Bio:             regReq.Bio,
		TermsAccepted:   regReq.TermsAccepted,
		PrivacyAccepted: regReq.PrivacyAccepted,
	}
	
	// Hash password
	if err := user.HashPassword(regReq.Password); err != nil {
		log.Printf("Failed to hash password: %v", err)
		return h.errorResponse(500, "Internal server error"), nil
	}
	
	// Save user to database
	if err := h.userRepo.CreateUser(user); err != nil {
		log.Printf("Failed to create user: %v", err)
		return h.errorResponse(500, "Failed to create user account"), nil
	}
	
	// Send verification email
	if err := h.emailService.SendVerificationEmail(user.Email, user.Username, user.EmailVerifyToken); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		// Don't fail the registration if email sending fails
		// The user can request a new verification email later
	}
	
	// Return success response
	response := models.UserRegistrationResponse{
		Success: true,
		Message: "Registration successful. Please check your email to verify your account.",
		UserID:  user.ID,
	}
	
	return h.successResponse(201, response), nil
}

// HandleVerifyEmail handles email verification requests
func (h *UserRegistrationHandler) HandleVerifyEmail(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.Printf("Handling email verification request")
	
	// Parse request body
	var verifyReq models.EmailVerificationRequest
	err := json.Unmarshal([]byte(request.Body), &verifyReq)
	if err != nil {
		log.Printf("Failed to parse verification request: %v", err)
		return h.errorResponse(400, "Invalid request body"), nil
	}
	
	// Validate token
	if verifyReq.Token == "" {
		return h.errorResponse(400, "Verification token is required"), nil
	}
	
	// Verify email using token
	if err := h.userRepo.VerifyEmail(verifyReq.Token); err != nil {
		log.Printf("Email verification failed: %v", err)
		if strings.Contains(err.Error(), "invalid verification token") {
			return h.errorResponse(400, "Invalid or expired verification token"), nil
		}
		return h.errorResponse(500, "Internal server error"), nil
	}
	
	// Send welcome email (optional, don't fail if it doesn't work)
	// We would need to get the user details to send the welcome email
	// For now, just return success
	
	response := models.EmailVerificationResponse{
		Success: true,
		Message: "Email verified successfully. Your account is now active.",
	}
	
	return h.successResponse(200, response), nil
}

// HandleOptions handles CORS preflight requests
func (h *UserRegistrationHandler) HandleOptions(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
		Body: "",
	}, nil
}

// validateRegistrationRequest validates the registration request
func (h *UserRegistrationHandler) validateRegistrationRequest(req *models.UserRegistrationRequest) error {
	// Validate username
	if err := req.ValidateUsername(); err != nil {
		return err
	}
	
	// Validate email
	if err := req.ValidateEmail(); err != nil {
		return err
	}
	
	// Validate password
	if err := req.ValidatePassword(); err != nil {
		return err
	}
	
	// Validate terms and privacy acceptance
	if err := req.ValidateTermsAndPrivacy(); err != nil {
		return err
	}
	
	// Validate optional fields
	if len(req.FirstName) > 50 {
		return fmt.Errorf("first name must be no more than 50 characters")
	}
	
	if len(req.LastName) > 50 {
		return fmt.Errorf("last name must be no more than 50 characters")
	}
	
	if len(req.Bio) > 500 {
		return fmt.Errorf("bio must be no more than 500 characters")
	}
	
	// Validate CAPTCHA token presence
	if req.CaptchaToken == "" {
		return fmt.Errorf("CAPTCHA verification is required")
	}
	
	return nil
}

// successResponse creates a successful API response
func (h *UserRegistrationHandler) successResponse(statusCode int, data interface{}) events.APIGatewayProxyResponse {
	body, _ := json.Marshal(data)
	
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(body),
	}
}

// errorResponse creates an error API response
func (h *UserRegistrationHandler) errorResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	errorResp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	
	body, _ := json.Marshal(errorResp)
	
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body: string(body),
	}
}