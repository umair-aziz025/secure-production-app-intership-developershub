/**
 * Vercel API Handler - CSRF Token
 */
const crypto = require('crypto');

module.exports = (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        // Generate a simple CSRF token
        const csrfToken = crypto.randomBytes(32).toString('hex');
        
        res.status(200).json({
            csrfToken,
            message: 'CSRF token generated successfully',
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('CSRF token error:', error);
        res.status(500).json({
            error: 'Failed to generate CSRF token',
            code: 'CSRF_GENERATION_ERROR'
        });
    }
};
