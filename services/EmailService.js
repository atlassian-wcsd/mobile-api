const nodemailer = require('nodemailer');
const config = require('../config/email.config');

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: config.host,
            port: config.port,
            secure: config.secure,
            auth: {
                user: config.user,
                pass: config.password
            }
        });
    }

    /**
     * Sends a verification email to the user
     * @param {string} to - Recipient's email address
     * @param {string} verificationToken - Token for email verification
     * @param {string} name - User's name
     * @returns {Promise} - Resolves when email is sent
     */
    async sendVerificationEmail(to, verificationToken, name) {
        try {
            const mailOptions = {
                from: config.from,
                to: to,
                subject: 'Verify Your Email Address',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2>Welcome to Our App!</h2>
                        <p>Hello ${name},</p>
                        <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${config.verificationUrl}?token=${verificationToken}" 
                               style="background-color: #4CAF50; color: white; padding: 14px 20px; 
                                      text-decoration: none; border-radius: 4px;">
                                Verify Email
                            </a>
                        </div>
                        <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
                        <p>${config.verificationUrl}?token=${verificationToken}</p>
                        <p>This link will expire in 24 hours.</p>
                        <p>If you didn't create an account, you can safely ignore this email.</p>
                        <p>Best regards,<br>Your App Team</p>
                    </div>
                `
            };

            const info = await this.transporter.sendMail(mailOptions);
            console.log('Verification email sent:', info.messageId);
            return info;
        } catch (error) {
            console.error('Error sending verification email:', error);
            throw new Error('Failed to send verification email');
        }
    }

    /**
     * Validates an email address format
     * @param {string} email - Email address to validate
     * @returns {boolean} - True if email format is valid
     */
    validateEmailFormat(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
}

module.exports = new EmailService();