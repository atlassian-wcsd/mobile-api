const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const EmailService = require('../services/EmailService');
const { generateVerificationToken } = require('../utils/tokenUtils');

class UserController {
    /**
     * Register a new user
     * @param {Request} req - Express request object
     * @param {Response} res - Express response object
     */
    async register(req, res) {
        try {
            // Validate request input
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array()
                });
            }

            const { name, email, password, phoneNumber } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email is already registered'
                });
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create verification token
            const verificationToken = generateVerificationToken();

            // Create new user
            const user = new User({
                name,
                email,
                password: hashedPassword,
                phoneNumber,
                verificationToken,
                isVerified: false
            });

            await user.save();

            // Send verification email
            await EmailService.sendVerificationEmail(email, verificationToken);

            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(201).json({
                success: true,
                message: 'Registration successful. Please check your email for verification.',
                token,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phoneNumber: user.phoneNumber,
                    isVerified: user.isVerified
                }
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during registration. Please try again.'
            });
        }
    }

    /**
     * Verify user email
     * @param {Request} req - Express request object
     * @param {Response} res - Express response object
     */
    async verifyEmail(req, res) {
        try {
            const { token } = req.params;

            const user = await User.findOne({ verificationToken: token });
            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid verification token'
                });
            }

            user.isVerified = true;
            user.verificationToken = undefined;
            await user.save();

            res.status(200).json({
                success: true,
                message: 'Email verified successfully'
            });

        } catch (error) {
            console.error('Email verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during email verification'
            });
        }
    }

    /**
     * Resend verification email
     * @param {Request} req - Express request object
     * @param {Response} res - Express response object
     */
    async resendVerification(req, res) {
        try {
            const { email } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            if (user.isVerified) {
                return res.status(400).json({
                    success: false,
                    message: 'Email is already verified'
                });
            }

            const verificationToken = generateVerificationToken();
            user.verificationToken = verificationToken;
            await user.save();

            await EmailService.sendVerificationEmail(email, verificationToken);

            res.status(200).json({
                success: true,
                message: 'Verification email sent successfully'
            });

        } catch (error) {
            console.error('Resend verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while resending verification email'
            });
        }
    }
}

module.exports = new UserController();