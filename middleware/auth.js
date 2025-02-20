const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/user');

/**
 * Authentication middleware for protecting routes
 * Verifies JWT token and attaches user to request object
 */
const auth = async (req, res, next) => {
    try {
        // Get token from Authorization header
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error('Authentication required');
        }

        // Verify token
        const decoded = jwt.verify(token, config.jwtSecret);
        
        // Find user by id and token
        const user = await User.findOne({ 
            _id: decoded._id,
            'tokens.token': token 
        });

        if (!user) {
            throw new Error('User not found');
        }

        // Check if email is verified
        if (!user.emailVerified) {
            throw new Error('Email not verified');
        }

        // Attach token and user to request object
        req.token = token;
        req.user = user;
        
        next();
    } catch (error) {
        res.status(401).json({ 
            error: 'Authentication failed',
            message: error.message 
        });
    }
};

/**
 * Middleware to check if user has admin role
 */
const adminAuth = async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'admin') {
            throw new Error('Admin access required');
        }
        next();
    } catch (error) {
        res.status(403).json({
            error: 'Access denied',
            message: error.message
        });
    }
};

module.exports = {
    auth,
    adminAuth
};