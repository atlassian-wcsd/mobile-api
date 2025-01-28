/**
 * LoggingService.js
 * Service for handling security and authentication-related logging
 */

class LoggingService {
    constructor() {
        this.LOG_LEVELS = {
            INFO: 'INFO',
            WARN: 'WARN',
            ERROR: 'ERROR',
            SECURITY: 'SECURITY'
        };
    }

    /**
     * Log a security event
     * @param {string} event - The security event type
     * @param {Object} details - Additional event details
     * @param {string} level - Log level (default: SECURITY)
     */
    logSecurityEvent(event, details, level = this.LOG_LEVELS.SECURITY) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            event,
            details,
            source: 'AUTH_SERVICE'
        };

        // In a production environment, this would send to a secure logging system
        console.log(JSON.stringify(logEntry));
        
        // For security events, we might want to trigger alerts or notifications
        if (level === this.LOG_LEVELS.SECURITY) {
            this.alertSecurityTeam(logEntry);
        }
    }

    /**
     * Log authentication attempts
     * @param {string} userId - User identifier
     * @param {boolean} success - Whether the authentication was successful
     * @param {Object} metadata - Additional authentication metadata
     */
    logAuthAttempt(userId, success, metadata = {}) {
        const event = success ? 'AUTH_SUCCESS' : 'AUTH_FAILURE';
        const details = {
            userId,
            ipAddress: metadata.ipAddress,
            userAgent: metadata.userAgent,
            timestamp: new Date().toISOString(),
            attemptNumber: metadata.attemptNumber
        };

        this.logSecurityEvent(event, details);
    }

    /**
     * Log password reset attempts
     * @param {string} userId - User identifier
     * @param {string} resetType - Type of reset (request/completion)
     * @param {Object} metadata - Additional reset metadata
     */
    logPasswordReset(userId, resetType, metadata = {}) {
        const event = `PASSWORD_RESET_${resetType.toUpperCase()}`;
        const details = {
            userId,
            ipAddress: metadata.ipAddress,
            userAgent: metadata.userAgent,
            timestamp: new Date().toISOString()
        };

        this.logSecurityEvent(event, details);
    }

    /**
     * Log MFA events
     * @param {string} userId - User identifier
     * @param {string} mfaType - Type of MFA used
     * @param {boolean} success - Whether the MFA attempt was successful
     * @param {Object} metadata - Additional MFA metadata
     */
    logMFAEvent(userId, mfaType, success, metadata = {}) {
        const event = success ? 'MFA_SUCCESS' : 'MFA_FAILURE';
        const details = {
            userId,
            mfaType,
            ipAddress: metadata.ipAddress,
            userAgent: metadata.userAgent,
            timestamp: new Date().toISOString()
        };

        this.logSecurityEvent(event, details);
    }

    /**
     * Log rate limiting events
     * @param {string} userId - User identifier
     * @param {string} actionType - Type of action being rate limited
     * @param {Object} metadata - Additional rate limiting metadata
     */
    logRateLimitEvent(userId, actionType, metadata = {}) {
        const event = 'RATE_LIMIT_EXCEEDED';
        const details = {
            userId,
            actionType,
            ipAddress: metadata.ipAddress,
            userAgent: metadata.userAgent,
            timestamp: new Date().toISOString(),
            threshold: metadata.threshold,
            windowSize: metadata.windowSize
        };

        this.logSecurityEvent(event, details, this.LOG_LEVELS.WARN);
    }

    /**
     * Alert security team of significant security events
     * @private
     * @param {Object} logEntry - The log entry to send
     */
    alertSecurityTeam(logEntry) {
        // Implementation would depend on the alert system being used
        // Could be email, SMS, Slack, etc.
        console.warn('SECURITY ALERT:', logEntry);
    }
}

export default new LoggingService();