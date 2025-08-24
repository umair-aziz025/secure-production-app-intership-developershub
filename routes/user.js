/**
 * 👤 USER ROUTES
 * User management and profile endpoints
 */

const express = require('express');
const router = express.Router();
const logger = require('../config/logger');
const database = require('../database/connection');

// Get user profile
router.get('/profile', async (req, res) => {
    try {
        const user = await database.getQuery(
            'SELECT id, username, email, profile_info, created_at, last_login FROM users WHERE id = ?',
            [req.user.id]
        );

        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        res.json(user);
    } catch (error) {
        logger.error('Get profile error', { error: error.message, userId: req.user.id });
        res.status(500).json({
            error: 'Failed to get profile',
            code: 'PROFILE_ERROR'
        });
    }
});

// Update user profile
router.put('/profile', async (req, res) => {
    try {
        const { profile_info } = req.body;

        await database.runQuery(
            'UPDATE users SET profile_info = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [profile_info, req.user.id]
        );

        // Log to audit trail
        await database.runQuery(`
            INSERT INTO audit_logs (user_id, action, resource, new_values, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            req.user.id,
            'PROFILE_UPDATE',
            'users',
            JSON.stringify({ profile_info }),
            req.ip,
            req.get('User-Agent')
        ]);

        logger.info('Profile updated', { userId: req.user.id });
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        logger.error('Update profile error', { error: error.message, userId: req.user.id });
        res.status(500).json({
            error: 'Failed to update profile',
            code: 'UPDATE_ERROR'
        });
    }
});

// Get user sessions
router.get('/sessions', async (req, res) => {
    try {
        const sessions = await database.allQuery(
            'SELECT id, created_at, last_accessed, ip_address, user_agent, is_active FROM user_sessions WHERE user_id = ? ORDER BY last_accessed DESC',
            [req.user.id]
        );

        res.json({
            sessions,
            count: sessions.length
        });
    } catch (error) {
        logger.error('Get sessions error', { error: error.message, userId: req.user.id });
        res.status(500).json({
            error: 'Failed to get sessions',
            code: 'SESSIONS_ERROR'
        });
    }
});

// Get user audit logs
router.get('/audit-logs', async (req, res) => {
    try {
        const logs = await database.allQuery(
            'SELECT action, resource, old_values, new_values, ip_address, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
            [req.user.id]
        );

        res.json({
            logs,
            count: logs.length
        });
    } catch (error) {
        logger.error('Get audit logs error', { error: error.message, userId: req.user.id });
        res.status(500).json({
            error: 'Failed to get audit logs',
            code: 'AUDIT_LOGS_ERROR'
        });
    }
});

// Delete user session
router.delete('/sessions/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;

        const result = await database.runQuery(
            'UPDATE user_sessions SET is_active = 0 WHERE id = ? AND user_id = ?',
            [sessionId, req.user.id]
        );

        if (result.changes === 0) {
            return res.status(404).json({
                error: 'Session not found',
                code: 'SESSION_NOT_FOUND'
            });
        }

        logger.info('Session terminated', { userId: req.user.id, sessionId });
        res.json({ message: 'Session terminated successfully' });
    } catch (error) {
        logger.error('Delete session error', { error: error.message, userId: req.user.id });
        res.status(500).json({
            error: 'Failed to terminate session',
            code: 'TERMINATE_SESSION_ERROR'
        });
    }
});

module.exports = router;
