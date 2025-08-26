package services

import (
	"fmt"
	"os"
	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
)

// EmailService handles sending emails
type EmailService struct {
	sesClient sesiface.SESAPI
	fromEmail string
	baseURL   string
}

// NewEmailService creates a new email service
func NewEmailService(sesClient sesiface.SESAPI) *EmailService {
	fromEmail := os.Getenv("FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@yourapp.com"
	}
	
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "https://yourapp.com"
	}
	
	return &EmailService{
		sesClient: sesClient,
		fromEmail: fromEmail,
		baseURL:   baseURL,
	}
}

// SendVerificationEmail sends an email verification email to the user
func (s *EmailService) SendVerificationEmail(email, username, verificationToken string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, verificationToken)
	
	subject := "Verify Your Email Address"
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Our App!</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>Thank you for registering with us! To complete your registration, please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
                <a href="%s" class="button">Verify Email Address</a>
            </p>
            <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
            <p><a href="%s">%s</a></p>
            <p>This verification link will expire in 24 hours for security reasons.</p>
            <p>If you didn't create an account with us, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
            <p>&copy; 2024 Your App. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, verificationURL, verificationURL, verificationURL)
	
	textBody := fmt.Sprintf(`
Hi %s,

Thank you for registering with us! To complete your registration, please verify your email address by visiting this link:

%s

This verification link will expire in 24 hours for security reasons.

If you didn't create an account with us, please ignore this email.

This is an automated message, please do not reply to this email.

© 2024 Your App. All rights reserved.
`, username, verificationURL)
	
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(email),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(htmlBody),
				},
				Text: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(textBody),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(s.fromEmail),
	}
	
	_, err := s.sesClient.SendEmail(input)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}
	
	return nil
}

// SendWelcomeEmail sends a welcome email after successful email verification
func (s *EmailService) SendWelcomeEmail(email, username string) error {
	subject := "Welcome to Our App!"
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #28a745; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Our App!</h1>
        </div>
        <div class="content">
            <h2>Hi %s,</h2>
            <p>Congratulations! Your email has been successfully verified and your account is now active.</p>
            <p>You can now enjoy all the features of our app. Here are some things you can do:</p>
            <ul>
                <li>Complete your profile</li>
                <li>Explore our features</li>
                <li>Connect with other users</li>
            </ul>
            <p style="text-align: center;">
                <a href="%s/login" class="button">Get Started</a>
            </p>
            <p>If you have any questions or need help, feel free to contact our support team.</p>
        </div>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
            <p>&copy; 2024 Your App. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, s.baseURL)
	
	textBody := fmt.Sprintf(`
Hi %s,

Congratulations! Your email has been successfully verified and your account is now active.

You can now enjoy all the features of our app. Here are some things you can do:
- Complete your profile
- Explore our features
- Connect with other users

Visit %s/login to get started.

If you have any questions or need help, feel free to contact our support team.

This is an automated message, please do not reply to this email.

© 2024 Your App. All rights reserved.
`, username, s.baseURL)
	
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(email),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(htmlBody),
				},
				Text: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(textBody),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(s.fromEmail),
	}
	
	_, err := s.sesClient.SendEmail(input)
	if err != nil {
		return fmt.Errorf("failed to send welcome email: %w", err)
	}
	
	return nil
}