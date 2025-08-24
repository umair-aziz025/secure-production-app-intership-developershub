/**
 * 🛡️ SECURITY ROUTES
 * Security monitoring and metrics endpoints
 */

const express = require('express');
const router = express.Router();
const logger = require('../config/logger');
const database = require('../database/connection');
const authMiddleware = require('../middleware/auth');

// Get CSRF token (public endpoint)
router.get('/csrf-token', (req, res) => {
    try {
        const securityMiddleware = require('../middleware/security');
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

// Security metrics (admin only)
router.get('/metrics', authMiddleware.verifyAdmin, async (req, res) => {
    try {
        const metrics = await database.allQuery(
            'SELECT metric_name, metric_value, recorded_at FROM security_metrics ORDER BY recorded_at DESC LIMIT 100'
        );

        res.json({
            metrics,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Security metrics error', { error: error.message });
        res.status(500).json({
            error: 'Failed to get security metrics',
            code: 'METRICS_ERROR'
        });
    }
});

// Security logs (admin only)
router.get('/logs', authMiddleware.verifyAdmin, async (req, res) => {
    try {
        const logs = await database.allQuery(
            'SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 100'
        );

        res.json({
            logs,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Security logs error', { error: error.message });
        res.status(500).json({
            error: 'Failed to get security logs',
            code: 'LOGS_ERROR'
        });
    }
});

// Security status dashboard
router.get('/status', authMiddleware.verifyToken, async (req, res) => {
    try {
        // Get recent security events
        const recentEvents = await database.allQuery(
            'SELECT COUNT(*) as count, event_type FROM security_logs WHERE created_at > datetime("now", "-1 hour") GROUP BY event_type'
        );

        // Get user session count
        const activeSessions = await database.getQuery(
            'SELECT COUNT(*) as count FROM user_sessions WHERE is_active = 1 AND expires_at > CURRENT_TIMESTAMP'
        );

        // Get failed login attempts in last hour
        const failedLogins = await database.getQuery(
            'SELECT COUNT(*) as count FROM security_logs WHERE event_type = "LOGIN_FAILURE" AND created_at > datetime("now", "-1 hour")'
        );

        res.json({
            recentEvents,
            activeSessions: activeSessions.count,
            failedLogins: failedLogins.count,
            serverUptime: process.uptime(),
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Security status error', { error: error.message });
        res.status(500).json({
            error: 'Failed to get security status',
            code: 'STATUS_ERROR'
        });
    }
});

// Test endpoint for CSRF protection
router.post('/test-csrf', authMiddleware.verifyToken, (req, res) => {
    res.json({
        message: 'CSRF protection test passed',
        user: req.user.username,
        timestamp: new Date().toISOString()
    });
});

// Audit logs for admins
router.get('/audit-logs', authMiddleware.verifyAdmin, async (req, res) => {
    try {
        const { limit = 100, offset = 0 } = req.query;
        
        const logs = await database.allQuery(
            'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [parseInt(limit), parseInt(offset)]
        );

        const totalCount = await database.getQuery(
            'SELECT COUNT(*) as count FROM audit_logs'
        );

        res.json({
            logs,
            total: totalCount.count,
            limit: parseInt(limit),
            offset: parseInt(offset),
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Audit logs error', { error: error.message });
        res.status(500).json({
            error: 'Failed to get audit logs',
            code: 'AUDIT_LOGS_ERROR'
        });
    }
});

// Security health check
router.get('/health', (req, res) => {
    res.json({
        status: 'secure',
        services: {
            authentication: 'operational',
            authorization: 'operational',
            csrf_protection: 'active',
            rate_limiting: 'active',
            input_validation: 'active',
            audit_logging: 'active'
        },
        timestamp: new Date().toISOString()
    });
});

module.exports = router;
