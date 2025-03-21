import { User } from '../models/User';
import { PasswordService } from './PasswordService';
import { SessionService } from './SessionService';
import { RateLimiter } from '../utils/RateLimiter';
import { Logger } from '../utils/Logger';
import { SecurityAuditor } from '../utils/SecurityAuditor';
import { Encryptor } from '../utils/Encryptor';
import { MFAService } from './MFAService';

export class AuthenticationService {
    private passwordService: PasswordService;
    private sessionService: SessionService;
    private rateLimiter: RateLimiter;
    private logger: Logger;
    private securityAuditor: SecurityAuditor;
    private encryptor: Encryptor;
    private mfaService: MFAService;

    constructor() {
        this.passwordService = new PasswordService();
        this.sessionService = new SessionService();
        this.rateLimiter = new RateLimiter();
        this.logger = new Logger();
        this.securityAuditor = new SecurityAuditor();
        this.encryptor = new Encryptor();
        this.mfaService = new MFAService();
    }

    /**
     * Authenticates a user with their credentials and handles MFA
     * @param email User's email
     * @param password User's password
     * @returns Promise<User> if authentication successful
     * @throws AuthenticationError for invalid credentials or rate limiting
     */
    async login(email: string, password: string): Promise<User> {
        try {
            // Check rate limiting
            if (this.rateLimiter.isLimited(email)) {
                throw new Error('Too many login attempts. Please try again later.');
            }

            // Encrypt sensitive data
            const encryptedEmail = this.encryptor.encrypt(email);
            const encryptedPassword = this.encryptor.encrypt(password);

            // Validate password strength
            if (!this.passwordService.validatePasswordStrength(password)) {
                throw new Error('Password does not meet security requirements.');
            }

            // Verify credentials
            const user = await this.verifyCredentials(encryptedEmail, encryptedPassword);

            // Handle MFA
            const mfaVerified = await this.mfaService.verify(user);
            if (!mfaVerified) {
                throw new Error('Multi-factor authentication failed.');
            }

            // Create session
            await this.sessionService.createSession(user);

            // Log successful login
            this.logger.logLoginActivity({
                userId: user.id,
                timestamp: new Date(),
                status: 'success',
                ipAddress: this.getClientIp()
            });

            return user;
        } catch (error) {
            // Log failed login attempt
            this.logger.logLoginActivity({
                email,
                timestamp: new Date(),
                status: 'failed',
                error: error.message,
                ipAddress: this.getClientIp()
            });

            throw error;
        }
    }

    /**
     * Logs out a user and terminates their session
     * @param userId User's ID
     */
    async logout(userId: string): Promise<void> {
        try {
            await this.sessionService.terminateSession(userId);
            this.logger.logLogoutActivity({
                userId,
                timestamp: new Date(),
                status: 'success'
            });
        } catch (error) {
            this.logger.logLogoutActivity({
                userId,
                timestamp: new Date(),
                status: 'failed',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Initiates password reset process
     * @param email User's email
     */
    async initiatePasswordReset(email: string): Promise<void> {
        try {
            await this.passwordService.initiateReset(email);
            this.logger.logPasswordResetRequest({
                email,
                timestamp: new Date(),
                status: 'initiated'
            });
        } catch (error) {
            this.logger.logPasswordResetRequest({
                email,
                timestamp: new Date(),
                status: 'failed',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Completes password reset process
     * @param token Reset token
     * @param newPassword New password
     */
    async completePasswordReset(token: string, newPassword: string): Promise<void> {
        try {
            if (!this.passwordService.validatePasswordStrength(newPassword)) {
                throw new Error('New password does not meet security requirements.');
            }

            await this.passwordService.completeReset(token, newPassword);
            this.logger.logPasswordResetCompletion({
                token,
                timestamp: new Date(),
                status: 'success'
            });
        } catch (error) {
            this.logger.logPasswordResetCompletion({
                token,
                timestamp: new Date(),
                status: 'failed',
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Verifies user credentials
     * @param encryptedEmail Encrypted email
     * @param encryptedPassword Encrypted password
     * @returns Promise<User>
     * @private
     */
    private async verifyCredentials(encryptedEmail: string, encryptedPassword: string): Promise<User> {
        // Implementation would verify against database
        // This is a placeholder
        throw new Error('Not implemented');
    }

    /**
     * Gets client IP address
     * @returns string
     * @private
     */
    private getClientIp(): string {
        // Implementation would get client IP from request
        // This is a placeholder
        return '0.0.0.0';
    }

    /**
     * Runs security audit
     * @returns Promise<void>
     */
    async runSecurityAudit(): Promise<void> {
        await this.securityAuditor.runAudit();
    }
}