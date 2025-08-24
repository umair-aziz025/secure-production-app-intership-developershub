/**
 * 📝 WINSTON LOGGER CONFIGURATION
 * Comprehensive logging system for security monitoring
 */

const winston = require('winston');
const path = require('path');

// Ensure logs directory exists
const fs = require('fs');
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
        return `${timestamp} [${level}]: ${message} ${metaStr}`;
    })
);

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: { 
        service: 'secure-production-app',
        version: process.env.APP_VERSION || '1.0.0'
    },
    transports: [
        // Error log file
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),
        
        // Security log file
        new winston.transports.File({
            filename: path.join(logsDir, 'security.log'),
            level: 'info',
            maxsize: 5242880, // 5MB
            maxFiles: 10,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),
        
        // Combined log file
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ],
    
    // Handle exceptions and rejections
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log')
        })
    ],
    
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log')
        })
    ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat,
        level: 'debug'
    }));
}

// Security-specific logging methods
logger.security = {
    loginAttempt: (data) => {
        logger.info('Login attempt', { 
            type: 'LOGIN_ATTEMPT', 
            ...data 
        });
    },
    
    loginSuccess: (data) => {
        logger.info('Successful login', { 
            type: 'LOGIN_SUCCESS', 
            ...data 
        });
    },
    
    loginFailure: (data) => {
        logger.warn('Failed login attempt', { 
            type: 'LOGIN_FAILURE', 
            ...data 
        });
    },
    
    suspiciousActivity: (data) => {
        logger.warn('Suspicious activity detected', { 
            type: 'SUSPICIOUS_ACTIVITY', 
            ...data 
        });
    },
    
    securityViolation: (data) => {
        logger.error('Security violation detected', { 
            type: 'SECURITY_VIOLATION', 
            ...data 
        });
    },
    
    rateLimitExceeded: (data) => {
        logger.warn('Rate limit exceeded', { 
            type: 'RATE_LIMIT_EXCEEDED', 
            ...data 
        });
    }
};

module.exports = logger;
