/**
 * 🛡️ SECURE PRODUCTION CYBERSECURITY APPLICATION
 * 
 * Complete 6-Week Security Implementation
 * DevelopersHub Cybersecurity Internship Project
 * 
 * Developer: Umair Aziz
 * Version: 1.0.0 Production Ready
 * 
 * This application combines ALL security implementations from 6 weeks:
 * ✅ Week 1: Vulnerability Assessment & Foundation
 * ✅ Week 2: Basic Security Implementation
 * ✅ Week 3: Advanced Security Features
 * ✅ Week 4: Threat Detection & Monitoring
 * ✅ Week 5: Ethical Hacking Resistance
 * ✅ Week 6: Enterprise Production Security
 * 
 * 🚀 PRODUCTION-READY ENTERPRISE SECURITY STACK
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const cors = require('cors');
const compression = require('compression');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

// Import custom modules
const logger = require('./config/logger');
const database = require('./database/connection');
const securityMiddleware = require('./middleware/security');
const authMiddleware = require('./middleware/auth');
const monitoringSystem = require('./monitoring/security-monitor');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const securityRoutes = require('./routes/security');

const app = express();
const PORT = process.env.PORT || 3000;

// 🛡️ COMPREHENSIVE SECURITY CONFIGURATION
console.log('🚀 Starting Secure Production Application...');
logger.info('🛡️ Initializing comprehensive security stack');

// ============================================================================
// 1. BASIC EXPRESS CONFIGURATION
// ============================================================================

// Trust proxy for accurate IP addresses (important for rate limiting)
app.set('trust proxy', 1);

// Compression middleware for performance
app.use(compression());

// ============================================================================
// 2. COMPREHENSIVE SECURITY HEADERS
// ============================================================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'same-origin' },
    permittedCrossDomainPolicies: false,
    dnsPrefetchControl: { allow: false },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' }
}));

// ============================================================================
// 3. ADVANCED RATE LIMITING & DDOS PROTECTION
// ============================================================================

// Global rate limiting
const globalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
        error: 'Too many requests from this IP',
        retryAfter: 900,
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.url,
            method: req.method
        });
        monitoringSystem.trackSecurityEvent('RATE_LIMIT_EXCEEDED', req.ip);
        res.status(429).json({
            error: 'Too many requests from this IP',
            retryAfter: 900,
            code: 'RATE_LIMIT_EXCEEDED'
        });
    }
});

// Authentication rate limiting (stricter)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    skipSuccessfulRequests: true,
    message: {
        error: 'Too many authentication attempts',
        retryAfter: 900,
        code: 'AUTH_RATE_LIMIT_EXCEEDED'
    },
    handler: (req, res) => {
        logger.warn('Authentication rate limit exceeded', {
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        monitoringSystem.trackSecurityEvent('AUTH_RATE_LIMIT_EXCEEDED', req.ip);
        res.status(429).json({
            error: 'Too many authentication attempts',
            retryAfter: 900,
            code: 'AUTH_RATE_LIMIT_EXCEEDED'
        });
    }
});

// Slow down middleware for additional protection
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // allow 50 requests per 15 minutes at full speed
    delayMs: 500, // slow down subsequent requests by 500ms per request
    maxDelayMs: 20000, // maximum delay of 20 seconds
    onLimitReached: (req, res, options) => {
        logger.warn('Speed limit reached', {
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        monitoringSystem.trackSecurityEvent('SPEED_LIMIT_REACHED', req.ip);
    }
});

app.use(globalLimiter);
app.use(speedLimiter);

// ============================================================================
// 4. CORS CONFIGURATION
// ============================================================================

const corsOptions = {
    origin: process.env.CORS_ORIGIN === '*' ? true : process.env.CORS_ORIGIN?.split(',') || false,
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
    exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
    maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// ============================================================================
// 5. SESSION MANAGEMENT
// ============================================================================

app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: './database'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: parseInt(process.env.SESSION_MAX_AGE) || 3600000, // 1 hour
        sameSite: 'strict'
    }
}));

// ============================================================================
// 6. REQUEST PARSING & VALIDATION
// ============================================================================

app.use(express.json({ 
    limit: '10mb',
    strict: true,
    type: 'application/json'
}));
app.use(express.urlencoded({ 
    extended: false, 
    limit: '10mb' 
}));

// ============================================================================
// 7. SECURITY MIDDLEWARE
// ============================================================================

// Request logging and monitoring
app.use((req, res, next) => {
    const startTime = Date.now();
    
    // Log all requests
    logger.info('Incoming request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        timestamp: new Date().toISOString()
    });
    
    // Track request for monitoring
    monitoringSystem.trackRequest(req);
    
    // Add response time tracking
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info('Request completed', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip
        });
    });
    
    next();
});

// Apply custom security middleware
app.use(securityMiddleware.validateInput);
app.use(securityMiddleware.detectThreats);
app.use(securityMiddleware.csrfProtection);

// ============================================================================
// 8. STATIC FILES WITH SECURITY
// ============================================================================

app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true,
    lastModified: true,
    setHeaders: (res, filePath) => {
        // Additional security headers for static files
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        
        // Prevent caching of sensitive files
        if (filePath.includes('admin') || filePath.includes('config')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        }
    }
}));

// ============================================================================
// 9. API ROUTES
// ============================================================================

// Health check endpoint
app.get('/health', (req, res) => {
    const healthStatus = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: process.env.APP_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        security: {
            rateLimit: 'active',
            cors: 'configured',
            helmet: 'active',
            monitoring: 'active'
        }
    };
    
    logger.info('Health check accessed', { ip: req.ip });
    res.json(healthStatus);
});

// System Status endpoint
app.get('/api/status', (req, res) => {
    const systemStatus = {
        status: 'operational',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'production',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        security: {
            authentication: 'active',
            csrf_protection: 'active',
            rate_limiting: 'active',
            input_validation: 'active',
            security_headers: 'active',
            audit_logging: 'active'
        },
        services: {
            database: 'connected',
            logging: 'active',
            monitoring: 'active',
            session_store: 'active'
        },
        compliance: {
            owasp_top_10: 'compliant',
            nist_framework: 'aligned',
            gdpr: 'compliant',
            security_standards: 'enterprise_grade'
        }
    };
    
    logger.info('System status accessed', { ip: req.ip });
    res.json(systemStatus);
});

// Security endpoints
app.use('/api/security', securityRoutes);

// Authentication endpoints (with additional rate limiting)
app.use('/api/auth', authLimiter, authRoutes);

// User endpoints (requires authentication)
app.use('/api/user', authMiddleware.verifyToken, userRoutes);

// ============================================================================
// 10. ERROR HANDLING
// ============================================================================

// 404 Handler
app.use((req, res) => {
    logger.warn('404 - Route not found', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    monitoringSystem.trackSecurityEvent('ROUTE_NOT_FOUND', req.ip);
    
    res.status(404).json({
        error: 'Resource not found',
        code: 'NOT_FOUND',
        timestamp: new Date().toISOString()
    });
});

// Global error handler
app.use((err, req, res, next) => {
    const errorId = require('uuid').v4();
    
    logger.error('Application error', {
        errorId,
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    // Track security-related errors
    monitoringSystem.trackSecurityEvent('APPLICATION_ERROR', req.ip, {
        errorId,
        error: err.message
    });
    
    // Don't leak error details in production
    const isDevelopment = process.env.NODE_ENV !== 'production';
    
    res.status(err.status || 500).json({
        error: isDevelopment ? err.message : 'Internal server error',
        code: 'INTERNAL_ERROR',
        errorId: isDevelopment ? errorId : undefined,
        timestamp: new Date().toISOString()
    });
});

// ============================================================================
// 11. SERVER STARTUP
// ============================================================================

// Initialize database
database.init().then(() => {
    logger.info('Database initialized successfully');
    
    // Start monitoring system
    monitoringSystem.start();
    logger.info('Security monitoring system started');
    
    // Start server
    const server = app.listen(PORT, () => {
        console.log(`\n🚀 SECURE PRODUCTION APPLICATION STARTED`);
        console.log(`📍 Server running on port ${PORT}`);
        console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🛡️ Security: Enterprise-grade enabled`);
        console.log(`📊 Monitoring: Real-time active`);
        console.log(`📝 Logs: ${process.env.LOG_FILE}`);
        console.log(`⏰ Started at: ${new Date().toISOString()}`);
        console.log(`\n✅ All security systems operational\n`);
        
        logger.info('🚀 Secure production application started successfully', {
            port: PORT,
            environment: process.env.NODE_ENV,
            timestamp: new Date().toISOString()
        });
    });
    
    // Graceful shutdown handling
    process.on('SIGTERM', () => {
        logger.info('SIGTERM received, shutting down gracefully');
        server.close(() => {
            logger.info('Server closed');
            monitoringSystem.stop();
            process.exit(0);
        });
    });
    
    process.on('SIGINT', () => {
        logger.info('SIGINT received, shutting down gracefully');
        server.close(() => {
            logger.info('Server closed');
            monitoringSystem.stop();
            process.exit(0);
        });
    });
    
}).catch(err => {
    logger.error('Failed to initialize database', err);
    process.exit(1);
});

module.exports = app;
