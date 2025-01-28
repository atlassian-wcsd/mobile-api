const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/emailService');
const { logLoginActivity } = require('../utils/auditLogger');

// Rate limiting configuration
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts, please try again after 15 minutes'
});

// Password strength validation middleware
const passwordValidation = [
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
        .withMessage('Password must include uppercase, lowercase, number and special character')
];

// User registration
router.post('/register', 
    [...passwordValidation,
    body('email').isEmail().normalizeEmail(),
    body('phone').isMobilePhone()],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password, phone } = req.body;

            // Check if user already exists
            let user = await User.findOne({ email });
            if (user) {
                return res.status(400).json({ message: 'User already exists' });
            }

            // Create new user
            user = new User({
                email,
                password,
                phone,
                mfaEnabled: false
            });

            // Hash password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            await user.save();

            // Send verification email
            await sendVerificationEmail(user.email);

            res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: 'Server error during registration' });
        }
    }
);

// User login
router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email, password, mfaCode } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            await logLoginActivity({
                userId: user._id,
                status: 'failed',
                reason: 'Invalid password'
            });
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check if MFA is enabled and verify code
        if (user.mfaEnabled) {
            if (!mfaCode) {
                return res.status(400).json({ message: 'MFA code required' });
            }
            const isMfaValid = await verifyMfaCode(user, mfaCode);
            if (!isMfaValid) {
                await logLoginActivity({
                    userId: user._id,
                    status: 'failed',
                    reason: 'Invalid MFA code'
                });
                return res.status(400).json({ message: 'Invalid MFA code' });
            }
        }

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Log successful login
        await logLoginActivity({
            userId: user._id,
            status: 'success'
        });

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Password reset request
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate reset token
        const resetToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send password reset email
        await sendPasswordResetEmail(email, resetToken);

        res.json({ message: 'Password reset link sent to your email' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset request' });
    }
});

// Reset password with token
router.post('/reset-password/:token', passwordValidation, async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({
            _id: decoded.userId,
            resetToken: token,
            resetTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.json({ message: 'Password reset successful' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during password reset' });
    }
});

// Enable/disable MFA
router.post('/mfa/toggle', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        user.mfaEnabled = !user.mfaEnabled;
        
        if (user.mfaEnabled) {
            // Generate and save MFA secret
            const secret = generateMfaSecret();
            user.mfaSecret = secret;
            // Return QR code for MFA setup
            const qrCode = await generateQRCode(secret);
            await user.save();
            res.json({ mfaEnabled: true, qrCode });
        } else {
            user.mfaSecret = undefined;
            await user.save();
            res.json({ mfaEnabled: false });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during MFA toggle' });
    }
});

// Logout (token invalidation)
router.post('/logout', auth, async (req, res) => {
    try {
        // Add token to blacklist or invalidate session
        await invalidateToken(req.token);
        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during logout' });
    }
});

module.exports = router;