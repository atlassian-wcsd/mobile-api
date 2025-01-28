import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import rateLimit from 'express-rate-limit';

class SessionService {
    constructor() {
        this.sessions = new Map();
        this.failedAttempts = new Map();
        this.MAX_FAILED_ATTEMPTS = 5;
        this.LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds
    }

    // Rate limiter configuration
    static loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // Limit each IP to 5 login requests per windowMs
        message: 'Too many login attempts, please try again later'
    });

    // Password strength validation
    validatePasswordStrength(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength) {
            throw new Error('Password must be at least 8 characters long');
        }
        if (!hasUpperCase || !hasLowerCase) {
            throw new Error('Password must contain both uppercase and lowercase letters');
        }
        if (!hasNumbers) {
            throw new Error('Password must contain at least one number');
        }
        if (!hasSpecialChar) {
            throw new Error('Password must contain at least one special character');
        }

        return true;
    }

    // Create new session
    async createSession(user, mfaVerified = false) {
        const sessionId = uuidv4();
        const session = {
            userId: user.id,
            email: user.email,
            mfaVerified,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        };

        this.sessions.set(sessionId, session);
        
        // Generate JWT token
        const token = jwt.sign(
            { sessionId, userId: user.id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        return { sessionId, token };
    }

    // Verify session
    verifySession(sessionId, token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const session = this.sessions.get(sessionId);

            if (!session) {
                throw new Error('Session not found');
            }

            if (session.expiresAt < new Date()) {
                this.sessions.delete(sessionId);
                throw new Error('Session expired');
            }

            if (!session.mfaVerified) {
                throw new Error('MFA verification required');
            }

            return session;
        } catch (error) {
            throw new Error('Invalid session: ' + error.message);
        }
    }

    // Handle login attempts and rate limiting
    async handleLoginAttempt(email, success) {
        if (!success) {
            const attempts = (this.failedAttempts.get(email) || 0) + 1;
            this.failedAttempts.set(email, attempts);

            if (attempts >= this.MAX_FAILED_ATTEMPTS) {
                const lockoutTime = Date.now();
                this.failedAttempts.set(email + '_lockout', lockoutTime);
                throw new Error('Account locked due to too many failed attempts');
            }
        } else {
            // Reset failed attempts on successful login
            this.failedAttempts.delete(email);
        }
    }

    // Check if account is locked
    isAccountLocked(email) {
        const lockoutTime = this.failedAttempts.get(email + '_lockout');
        if (lockoutTime) {
            const timePassed = Date.now() - lockoutTime;
            if (timePassed < this.LOCKOUT_DURATION) {
                const remainingTime = Math.ceil((this.LOCKOUT_DURATION - timePassed) / 60000);
                throw new Error(`Account is locked. Try again in ${remainingTime} minutes`);
            }
            // Reset lockout after duration has passed
            this.failedAttempts.delete(email + '_lockout');
            this.failedAttempts.delete(email);
        }
        return false;
    }

    // Destroy session (logout)
    destroySession(sessionId) {
        if (this.sessions.has(sessionId)) {
            this.sessions.delete(sessionId);
            return true;
        }
        return false;
    }

    // Generate password reset token
    async generatePasswordResetToken(email) {
        const resetToken = uuidv4();
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        // Store reset token (in practice, this would be in a database)
        this.sessions.set(`reset_${resetToken}`, {
            email,
            expiresAt
        });

        return resetToken;
    }

    // Verify password reset token
    async verifyPasswordResetToken(token) {
        const resetData = this.sessions.get(`reset_${token}`);
        
        if (!resetData) {
            throw new Error('Invalid or expired reset token');
        }

        if (resetData.expiresAt < new Date()) {
            this.sessions.delete(`reset_${token}`);
            throw new Error('Reset token has expired');
        }

        return resetData.email;
    }

    // Log security event
    logSecurityEvent(event) {
        const logEntry = {
            timestamp: new Date(),
            event,
            // Add additional context as needed
        };

        // In practice, this would write to a secure logging system
        console.log('Security Event:', logEntry);
    }
}

export default new SessionService();