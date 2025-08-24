/**
 * 🔐 AUTHENTICATION ROUTES
 * Secure user authentication and session management
 */

const express = require('express');
const bcrypt = require('bcrypt');
const validator = require('validator');
const logger = require('../config/logger');
const database = require('../database/connection');
const authMiddleware = require('../middleware/auth');
const securityMiddleware = require('../middleware/security');

const router = express.Router();

// Get CSRF token
router.get('/csrf-token', (req, res) => {
    try {
        const sessionId = req.sessionID || req.ip;
        const csrfToken = securityMiddleware.generateCSRFToken(sessionId);
        
        res.json({
            csrfToken,
            message: 'CSRF token generated successfully'
        });
    } catch (error) {
        logger.error('CSRF token generation failed', { error: error.message });
        res.status(500).json({
            error: 'Failed to generate CSRF token',
            code: 'CSRF_GENERATION_ERROR'
        });
    }
});

// User Registration
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, profile_info } = req.body;

        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({
                error: 'Username, email, and password are required',
                code: 'MISSING_REQUIRED_FIELDS'
            });
        }

        // Validate email format
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                error: 'Invalid email format',
                code: 'INVALID_EMAIL'
            });
        }

        // Validate username format
        if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
            return res.status(400).json({
                error: 'Username must be 3-30 characters (letters, numbers, underscore only)',
                code: 'INVALID_USERNAME'
            });
        }

        // Validate password strength
        if (password.length < 8 || password.length > 128) {
            return res.status(400).json({
                error: 'Password must be 8-128 characters long',
                code: 'INVALID_PASSWORD_LENGTH'
            });
        }

        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/.test(password)) {
            return res.status(400).json({
                error: 'Password must contain uppercase, lowercase, number, and special character',
                code: 'WEAK_PASSWORD'
            });
        }

        // Check if user already exists
        const existingUser = await database.getQuery(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUser) {
            logger.security.suspiciousActivity({
                type: 'DUPLICATE_REGISTRATION_ATTEMPT',
                username,
                email,
                ip: req.ip
            });

            return res.status(409).json({
                error: 'Username or email already exists',
                code: 'USER_EXISTS'
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);

        // Create user
        const result = await database.runQuery(`
            INSERT INTO users (username, email, password_hash, profile_info, password_changed_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        `, [username, email, passwordHash, profile_info || '']);

        // Log successful registration
        logger.info('User registered successfully', {
            userId: result.id,
            username,
            email,
            ip: req.ip
        });

        // Log to audit trail
        await database.runQuery(`
            INSERT INTO audit_logs (user_id, action, resource, new_values, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            result.id,
            'USER_REGISTRATION',
            'users',
            JSON.stringify({ username, email }),
            req.ip,
            req.get('User-Agent')
        ]);

        res.status(201).json({
            message: 'User registered successfully',
            userId: result.id,
            username
        });

    } catch (error) {
        logger.error('Registration error', {
            error: error.message,
            ip: req.ip,
            body: { ...req.body, password: '[REDACTED]' }
        });

        res.status(500).json({
            error: 'Registration failed',
            code: 'REGISTRATION_ERROR'
        });
    }
});

// User Login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Input validation
        if (!username || !password) {
            return res.status(400).json({
                error: 'Username and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        // Log login attempt
        logger.security.loginAttempt({
            username,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        // Get user from database
        const user = await database.getQuery(
            'SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1',
            [username, username]
        );

        if (!user) {
            logger.security.loginFailure({
                username,
                reason: 'USER_NOT_FOUND',
                ip: req.ip
            });

            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Check if account is locked
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            logger.security.loginFailure({
                username,
                userId: user.id,
                reason: 'ACCOUNT_LOCKED',
                ip: req.ip
            });

            return res.status(423).json({
                error: 'Account temporarily locked due to multiple failed attempts',
                code: 'ACCOUNT_LOCKED'
            });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            // Increment login attempts
            const newAttempts = (user.login_attempts || 0) + 1;
            let lockUntil = null;

            // Lock account after 5 failed attempts
            if (newAttempts >= 5) {
                lockUntil = new Date(Date.now() + (30 * 60 * 1000)); // 30 minutes
            }

            await database.runQuery(
                'UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                [newAttempts, lockUntil?.toISOString(), user.id]
            );

            logger.security.loginFailure({
                username,
                userId: user.id,
                reason: 'INVALID_PASSWORD',
                attempts: newAttempts,
                ip: req.ip
            });

            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Reset login attempts on successful login
        await database.runQuery(
            'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP, last_login_ip = ? WHERE id = ?',
            [req.ip, user.id]
        );

        // Generate tokens
        const token = authMiddleware.generateToken(user);
        const refreshToken = authMiddleware.generateRefreshToken();

        // Create session in database
        await authMiddleware.createSession(user.id, token, refreshToken, req);

        // Log successful login
        logger.security.loginSuccess({
            username,
            userId: user.id,
            ip: req.ip
        });

        // Log to audit trail
        await database.runQuery(`
            INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `, [
            user.id,
            'USER_LOGIN',
            'authentication',
            req.ip,
            req.get('User-Agent')
        ]);

        res.json({
            message: 'Login successful',
            token,
            refreshToken,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin,
                lastLogin: user.last_login
            },
            expiresIn: 3600 // 1 hour
        });

    } catch (error) {
        logger.error('Login error', {
            error: error.message,
            ip: req.ip,
            body: { ...req.body, password: '[REDACTED]' }
        });

        res.status(500).json({
            error: 'Login failed',
            code: 'LOGIN_ERROR'
        });
    }
});

// User Logout
router.post('/logout', authMiddleware.verifyToken, async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader?.substring(7);

        if (token) {
            await authMiddleware.invalidateSession(req.user.id, token);
        }

        // Log logout
        logger.info('User logged out', {
            userId: req.user.id,
            username: req.user.username,
            ip: req.ip
        });

        // Log to audit trail
        await database.runQuery(`
            INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        `, [
            req.user.id,
            'USER_LOGOUT',
            'authentication',
            req.ip,
            req.get('User-Agent')
        ]);

        res.json({
            message: 'Logout successful'
        });

    } catch (error) {
        logger.error('Logout error', {
            error: error.message,
            userId: req.user?.id,
            ip: req.ip
        });

        res.status(500).json({
            error: 'Logout failed',
            code: 'LOGOUT_ERROR'
        });
    }
});

// Refresh Token
router.post('/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({
                error: 'Refresh token required',
                code: 'REFRESH_TOKEN_MISSING'
            });
        }

        // Verify refresh token
        const decoded = authMiddleware.verifyRefreshToken(refreshToken);
        if (!decoded) {
            return res.status(401).json({
                error: 'Invalid refresh token',
                code: 'INVALID_REFRESH_TOKEN'
            });
        }

        // Find active session with this refresh token
        const session = await database.getQuery(
            'SELECT * FROM user_sessions WHERE refresh_token = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP',
            [refreshToken]
        );

        if (!session) {
            return res.status(401).json({
                error: 'Refresh token not found or expired',
                code: 'REFRESH_TOKEN_EXPIRED'
            });
        }

        // Get user
        const user = await database.getQuery(
            'SELECT * FROM users WHERE id = ? AND is_active = 1',
            [session.user_id]
        );

        if (!user) {
            return res.status(401).json({
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Generate new tokens
        const newToken = authMiddleware.generateToken(user);
        const newRefreshToken = authMiddleware.generateRefreshToken();

        // Update session
        await database.runQuery(
            'UPDATE user_sessions SET session_token = ?, refresh_token = ?, last_accessed = CURRENT_TIMESTAMP WHERE id = ?',
            [newToken, newRefreshToken, session.id]
        );

        logger.info('Token refreshed', {
            userId: user.id,
            username: user.username,
            ip: req.ip
        });

        res.json({
            message: 'Token refreshed successfully',
            token: newToken,
            refreshToken: newRefreshToken,
            expiresIn: 3600
        });

    } catch (error) {
        logger.error('Token refresh error', {
            error: error.message,
            ip: req.ip
        });

        res.status(500).json({
            error: 'Token refresh failed',
            code: 'REFRESH_ERROR'
        });
    }
});

module.exports = router;
