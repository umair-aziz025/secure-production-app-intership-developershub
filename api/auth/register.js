/**
 * Vercel API Handler - User Registration
 */
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
        const { username, email, password, profile_info } = req.body;

        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({
                error: 'Username, email, and password are required',
                code: 'MISSING_REQUIRED_FIELDS'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
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
        if (password.length < 8) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters long',
                code: 'WEAK_PASSWORD'
            });
        }

        // Simulate user creation (in production, save to database)
        const newUser = {
            id: Math.floor(Math.random() * 10000),
            username,
            email,
            created_at: new Date().toISOString()
        };

        res.status(201).json({
            message: 'User registered successfully',
            userId: newUser.id,
            username: newUser.username
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            error: 'Registration failed',
            code: 'REGISTRATION_ERROR'
        });
    }
};
