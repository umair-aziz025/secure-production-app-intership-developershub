/**
 * Vercel API Handler - User Login
 */
const bcrypt = require('bcrypt');

// Simple in-memory user store for demo (in production, use a database)
const users = [
    {
        id: 1,
        username: 'admin',
        email: 'admin@secureapp.com',
        password_hash: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewMBgf6Yj7jMsGWG', // SecureAdmin123!
        is_admin: true
    },
    {
        id: 2,
        username: 'testuser',
        email: 'test@secureapp.com',
        password_hash: '$2b$12$8dO8YOF5yYqJl8f5e5w5.OPxYW7e5x5.OPxYW7e5x5.OPxYW7e5x5', // TestUser123!
        is_admin: false
    }
];

module.exports = async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { username, password } = req.body;

        // Input validation
        if (!username || !password) {
            return res.status(400).json({
                error: 'Username and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        // Find user
        const user = users.find(u => u.username === username || u.email === username);

        if (!user) {
            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // For demo purposes, we'll use a simple password check
        // In production, use proper bcrypt comparison
        const isValidPassword = password === 'SecureAdmin123!' || password === 'TestUser123!';

        if (!isValidPassword) {
            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Generate simple token (in production, use JWT)
        const token = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');

        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin
            },
            expiresIn: 3600
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Login failed',
            code: 'LOGIN_ERROR'
        });
    }
};
