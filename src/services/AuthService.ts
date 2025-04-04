import { injectable } from 'inversify';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { Logger } from '../utils/Logger';

@injectable()
export class AuthService {
    private readonly saltRounds = 10;
    private readonly jwtSecret = process.env.JWT_SECRET || 'default-secret-key';
    private readonly emailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: false,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });

    constructor(private readonly logger: Logger) {}

    async registerUser(userData: {
        email: string;
        password: string;
        firstName: string;
        lastName: string;
        captchaToken: string;
    }): Promise<{ success: boolean; message: string }> {
        try {
            // Validate captcha
            const isCaptchaValid = await this.validateCaptcha(userData.captchaToken);
            if (!isCaptchaValid) {
                return { success: false, message: 'Invalid CAPTCHA verification' };
            }

            // Validate password strength
            if (!this.isPasswordStrong(userData.password)) {
                return {
                    success: false,
                    message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
                };
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(userData.password, this.saltRounds);

            // Generate verification token
            const verificationToken = uuidv4();

            // Store user in database with verification token
            // TODO: Implement database storage
            
            // Send verification email
            await this.sendVerificationEmail(userData.email, verificationToken);

            this.logger.info(`User registration initiated for email: ${userData.email}`);
            return { success: true, message: 'Registration successful. Please check your email for verification.' };
        } catch (error) {
            this.logger.error('Error during user registration:', error);
            return { success: false, message: 'Registration failed. Please try again later.' };
        }
    }

    async verifyEmail(token: string): Promise<boolean> {
        try {
            // TODO: Implement email verification logic with database
            this.logger.info(`Email verification successful for token: ${token}`);
            return true;
        } catch (error) {
            this.logger.error('Error during email verification:', error);
            return false;
        }
    }

    async initiatePasswordReset(email: string): Promise<{ success: boolean; message: string }> {
        try {
            // Generate reset token
            const resetToken = uuidv4();
            
            // Store reset token in database with expiration
            // TODO: Implement database storage

            // Send password reset email
            await this.sendPasswordResetEmail(email, resetToken);

            this.logger.info(`Password reset initiated for email: ${email}`);
            return { success: true, message: 'Password reset instructions sent to your email.' };
        } catch (error) {
            this.logger.error('Error during password reset initiation:', error);
            return { success: false, message: 'Failed to initiate password reset. Please try again later.' };
        }
    }

    async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; message: string }> {
        try {
            // Validate password strength
            if (!this.isPasswordStrong(newPassword)) {
                return {
                    success: false,
                    message: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
                };
            }

            // Verify token and update password in database
            // TODO: Implement database update logic

            this.logger.info('Password reset successful');
            return { success: true, message: 'Password has been successfully reset.' };
        } catch (error) {
            this.logger.error('Error during password reset:', error);
            return { success: false, message: 'Failed to reset password. Please try again later.' };
        }
    }

    async updateUserProfile(userId: string, updateData: {
        firstName?: string;
        lastName?: string;
        email?: string;
    }): Promise<{ success: boolean; message: string }> {
        try {
            // TODO: Implement profile update logic with database
            this.logger.info(`Profile updated for user: ${userId}`);
            return { success: true, message: 'Profile updated successfully.' };
        } catch (error) {
            this.logger.error('Error during profile update:', error);
            return { success: false, message: 'Failed to update profile. Please try again later.' };
        }
    }

    private async validateCaptcha(token: string): Promise<boolean> {
        try {
            // TODO: Implement actual CAPTCHA validation logic
            return true;
        } catch (error) {
            this.logger.error('Error validating CAPTCHA:', error);
            return false;
        }
    }

    private isPasswordStrong(password: string): boolean {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        return password.length >= minLength &&
            hasUpperCase &&
            hasLowerCase &&
            hasNumbers &&
            hasSpecialChar;
    }

    private async sendVerificationEmail(email: string, token: string): Promise<void> {
        const verificationLink = `${process.env.APP_URL}/verify-email?token=${token}`;
        
        await this.emailTransporter.sendMail({
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'Verify Your Email Address',
            html: `
                <h1>Welcome to MFIRST!</h1>
                <p>Please click the link below to verify your email address:</p>
                <a href="${verificationLink}">${verificationLink}</a>
                <p>If you didn't create an account, please ignore this email.</p>
            `
        });
    }

    private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
        const resetLink = `${process.env.APP_URL}/reset-password?token=${token}`;
        
        await this.emailTransporter.sendMail({
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <h1>Password Reset Request</h1>
                <p>Please click the link below to reset your password:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>If you didn't request a password reset, please ignore this email.</p>
            `
        });
    }
}