/**
 * Vercel API Handler - Health Check
 */
module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    const healthStatus = {
        status: 'healthy',
        service: 'Secure Production App',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        environment: 'production',
        uptime: process.uptime(),
        security: {
            authentication: 'active',
            csrf_protection: 'active',
            rate_limiting: 'active',
            input_validation: 'active'
        }
    };

    res.status(200).json(healthStatus);
};
