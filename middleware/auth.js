/**
 * 🔐 AUTHENTICATION MIDDLEWARE
 * JWT token verification and user authorization
 */

const jwt = require('jsonwebtoken');
const logger = require('../config/logger');
const database = require('../database/connection');

class AuthMiddleware {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || 'fallback_secret_key';
        this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    }

    // Verify JWT token
    verifyToken = async (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            const token = authHeader && authHeader.startsWith('Bearer ') 
                ? authHeader.substring(7) 
                : null;

            if (!token) {
                logger.security.suspiciousActivity({
                    type: 'MISSING_AUTH_TOKEN',
                    ip: req.ip,
                    url: req.url,
                    userAgent: req.get('User-Agent')
                });

                return res.status(401).json({
                    error: 'Access token required',
                    code: 'TOKEN_MISSING'
                });
            }

            // Verify JWT token
            const decoded = jwt.verify(token, this.jwtSecret);

            // Check if user still exists and is active
            const user = await database.getQuery(
                'SELECT id, username, email, is_admin, is_active FROM users WHERE id = ? AND is_active = 1',
                [decoded.id]
            );

            if (!user) {
                logger.security.securityViolation({
                    type: 'INVALID_USER_TOKEN',
                    ip: req.ip,
                    userId: decoded.id,
                    username: decoded.username
                });

                return res.status(401).json({
                    error: 'Invalid token - user not found or inactive',
                    code: 'TOKEN_INVALID_USER'
                });
            }

            // Check if token is still valid in database
            const activeSession = await database.getQuery(
                'SELECT id FROM user_sessions WHERE user_id = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP',
                [user.id]
            );

            if (!activeSession) {
                logger.security.securityViolation({
                    type: 'EXPIRED_SESSION',
                    ip: req.ip,
                    userId: user.id,
                    username: user.username
                });

                return res.status(401).json({
                    error: 'Session expired',
                    code: 'SESSION_EXPIRED'
                });
            }

            // Update last accessed time
            await database.runQuery(
                'UPDATE user_sessions SET last_accessed = CURRENT_TIMESTAMP WHERE user_id = ? AND is_active = 1',
                [user.id]
            );

            // Add user to request object
            req.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin,
                iat: decoded.iat,
                exp: decoded.exp
            };

            // Log successful token verification
            logger.info('Token verified successfully', {
                userId: user.id,
                username: user.username,
                ip: req.ip,
                url: req.url
            });

            next();

        } catch (error) {
            let errorType = 'TOKEN_VERIFICATION_ERROR';
            let errorMessage = 'Token verification failed';

            if (error.name === 'JsonWebTokenError') {
                errorType = 'TOKEN_INVALID';
                errorMessage = 'Invalid token';
            } else if (error.name === 'TokenExpiredError') {
                errorType = 'TOKEN_EXPIRED';
                errorMessage = 'Token expired';
            }

            logger.security.securityViolation({
                type: errorType,
                error: error.message,
                ip: req.ip,
                url: req.url,
                userAgent: req.get('User-Agent')
            });

            return res.status(401).json({
                error: errorMessage,
                code: errorType
            });
        }
    };

    // Verify admin role
    verifyAdmin = (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        if (!req.user.isAdmin) {
            logger.security.suspiciousActivity({
                type: 'UNAUTHORIZED_ADMIN_ACCESS',
                userId: req.user.id,
                username: req.user.username,
                ip: req.ip,
                url: req.url
            });

            return res.status(403).json({
                error: 'Admin access required',
                code: 'ADMIN_REQUIRED'
            });
        }

        logger.info('Admin access granted', {
            userId: req.user.id,
            username: req.user.username,
            ip: req.ip,
            url: req.url
        });

        next();
    };

    // Optional authentication (allows both authenticated and anonymous access)
    optionalAuth = async (req, res, next) => {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.startsWith('Bearer ') 
            ? authHeader.substring(7) 
            : null;

        if (!token) {
            // No token provided, continue as anonymous user
            req.user = null;
            return next();
        }

        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            
            const user = await database.getQuery(
                'SELECT id, username, email, is_admin, is_active FROM users WHERE id = ? AND is_active = 1',
                [decoded.id]
            );

            if (user) {
                req.user = {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    isAdmin: user.is_admin,
                    iat: decoded.iat,
                    exp: decoded.exp
                };
            } else {
                req.user = null;
            }
        } catch (error) {
            // Invalid token, continue as anonymous user
            req.user = null;
        }

        next();
    };

    // Generate JWT token
    generateToken(user) {
        const payload = {
            id: user.id,
            username: user.username,
            email: user.email,
            isAdmin: user.is_admin || false,
            iat: Math.floor(Date.now() / 1000)
        };

        return jwt.sign(payload, this.jwtSecret, {
            expiresIn: this.jwtExpiresIn
        });
    }

    // Generate refresh token
    generateRefreshToken() {
        return jwt.sign(
            { type: 'refresh', iat: Math.floor(Date.now() / 1000) },
            this.jwtSecret,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
        );
    }

    // Verify refresh token
    verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            return decoded.type === 'refresh' ? decoded : null;
        } catch (error) {
            return null;
        }
    }

    // Create user session in database
    async createSession(userId, token, refreshToken, req) {
        try {
            const expiresAt = new Date(Date.now() + (60 * 60 * 1000)); // 1 hour
            
            await database.runQuery(`
                INSERT INTO user_sessions (
                    user_id, session_token, refresh_token, 
                    ip_address, user_agent, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            `, [
                userId,
                token,
                refreshToken,
                req.ip,
                req.get('User-Agent'),
                expiresAt.toISOString()
            ]);

            logger.info('User session created', {
                userId,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });

        } catch (error) {
            logger.error('Failed to create user session', {
                error: error.message,
                userId
            });
        }
    }

    // Invalidate user session
    async invalidateSession(userId, token) {
        try {
            await database.runQuery(
                'UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND session_token = ?',
                [userId, token]
            );

            logger.info('User session invalidated', { userId });
        } catch (error) {
            logger.error('Failed to invalidate session', {
                error: error.message,
                userId
            });
        }
    }

    // Invalidate all user sessions
    async invalidateAllSessions(userId) {
        try {
            await database.runQuery(
                'UPDATE user_sessions SET is_active = 0 WHERE user_id = ?',
                [userId]
            );

            logger.info('All user sessions invalidated', { userId });
        } catch (error) {
            logger.error('Failed to invalidate all sessions', {
                error: error.message,
                userId
            });
        }
    }
}

module.exports = new AuthMiddleware();
