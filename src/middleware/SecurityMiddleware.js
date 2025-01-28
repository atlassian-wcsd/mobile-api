const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Rate limiting configuration
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per window
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

// Password strength validation
const passwordValidationRules = [
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

// Request validation middleware
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Session validation middleware
const validateSession = (req, res, next) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ message: 'Invalid session' });
    }
    next();
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
    // Set security headers
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
    });
    next();
};

// Audit logging middleware
const auditLog = (req, res, next) => {
    const logData = {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        method: req.method,
        path: req.path,
        userId: req.user ? req.user.id : 'anonymous',
        userAgent: req.headers['user-agent']
    };
    
    console.log('Security Audit Log:', JSON.stringify(logData));
    next();
};

module.exports = {
    loginLimiter,
    passwordValidationRules,
    validateRequest,
    authenticateToken,
    validateSession,
    securityHeaders,
    auditLog
};