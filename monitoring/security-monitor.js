/**
 * 📊 SECURITY MONITORING SYSTEM
 * Real-time security event tracking and monitoring
 */

const logger = require('../config/logger');

class SecurityMonitor {
    constructor() {
        this.metrics = new Map();
        this.events = [];
        this.isRunning = false;
        this.alertThresholds = {
            RATE_LIMIT_EXCEEDED: 10,
            FAILED_LOGIN: 5,
            SECURITY_VIOLATION: 3
        };
    }

    start() {
        this.isRunning = true;
        logger.info('Security monitoring system started');
        
        // Start periodic cleanup
        setInterval(() => {
            this.cleanupOldEvents();
        }, 300000); // 5 minutes
    }

    stop() {
        this.isRunning = false;
        logger.info('Security monitoring system stopped');
    }

    trackSecurityEvent(eventType, ip, additionalData = {}) {
        if (!this.isRunning) return;

        const event = {
            type: eventType,
            ip,
            timestamp: new Date().toISOString(),
            ...additionalData
        };

        this.events.push(event);
        this.updateMetrics(eventType);

        // Check for alerts
        this.checkAlertThresholds(eventType, ip);

        logger.info('Security event tracked', event);
    }

    trackRequest(req) {
        if (!this.isRunning) return;

        this.updateMetrics('TOTAL_REQUESTS');
        
        // Track request details for monitoring
        const requestData = {
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        };

        // Store recent requests (keep last 1000)
        if (!this.recentRequests) {
            this.recentRequests = [];
        }
        
        this.recentRequests.push(requestData);
        if (this.recentRequests.length > 1000) {
            this.recentRequests.shift();
        }
    }

    updateMetrics(metricName) {
        const current = this.metrics.get(metricName) || 0;
        this.metrics.set(metricName, current + 1);
    }

    checkAlertThresholds(eventType, ip) {
        const threshold = this.alertThresholds[eventType];
        if (!threshold) return;

        // Count events of this type in the last hour
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const recentEvents = this.events.filter(event => 
            event.type === eventType && 
            event.ip === ip &&
            new Date(event.timestamp) > oneHourAgo
        );

        if (recentEvents.length >= threshold) {
            this.triggerAlert(eventType, ip, recentEvents.length);
        }
    }

    triggerAlert(eventType, ip, count) {
        const alertData = {
            type: 'SECURITY_ALERT',
            eventType,
            ip,
            count,
            threshold: this.alertThresholds[eventType],
            timestamp: new Date().toISOString()
        };

        logger.warn('🚨 SECURITY ALERT TRIGGERED', alertData);
        
        // In production, this would send alerts to security team
        console.log(`🚨 SECURITY ALERT: ${eventType} from ${ip} (${count} events)`);
    }

    cleanupOldEvents() {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        this.events = this.events.filter(event => 
            new Date(event.timestamp) > twentyFourHoursAgo
        );

        logger.info('Security events cleanup completed', { 
            eventsRetained: this.events.length 
        });
    }

    getMetrics() {
        return Object.fromEntries(this.metrics);
    }

    getRecentEvents(limit = 50) {
        return this.events.slice(-limit);
    }

    getSecuritySummary() {
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        
        const recentEvents = this.events.filter(event => 
            new Date(event.timestamp) > oneHourAgo
        );

        const eventTypes = {};
        recentEvents.forEach(event => {
            eventTypes[event.type] = (eventTypes[event.type] || 0) + 1;
        });

        return {
            totalEvents: this.events.length,
            recentEvents: recentEvents.length,
            eventTypes,
            metrics: this.getMetrics(),
            lastUpdated: now.toISOString()
        };
    }
}

module.exports = new SecurityMonitor();
