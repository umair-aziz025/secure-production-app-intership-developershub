/**
 * 🗄️ DATABASE CONNECTION & INITIALIZATION
 * Secure SQLite database setup with comprehensive schema
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const logger = require('../config/logger');

class Database {
    constructor() {
        this.db = null;
        this.dbPath = process.env.DB_PATH || path.join(__dirname, 'secure_production.db');
    }

    async init() {
        return new Promise((resolve, reject) => {
            this.db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    logger.error('Database connection failed', { error: err.message });
                    reject(err);
                } else {
                    logger.info('Database connected successfully', { path: this.dbPath });
                    this.createTables().then(resolve).catch(reject);
                }
            });
        });
    }

    async createTables() {
        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                profile_info TEXT,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                email_verified BOOLEAN DEFAULT 0,
                two_factor_enabled BOOLEAN DEFAULT 0,
                two_factor_secret TEXT,
                login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME,
                last_login DATETIME,
                last_login_ip TEXT,
                password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `;

        const createSecurityLogsTable = `
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                event_data TEXT,
                ip_address TEXT,
                user_agent TEXT,
                risk_level TEXT DEFAULT 'LOW',
                status TEXT DEFAULT 'DETECTED',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `;

        const createSessionsTable = `
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                refresh_token TEXT UNIQUE,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT 1,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `;

        const createAuditLogsTable = `
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `;

        const createSecurityMetricsTable = `
            CREATE TABLE IF NOT EXISTS security_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value INTEGER DEFAULT 0,
                metric_data TEXT,
                recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `;

        const createPasswordHistoryTable = `
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `;

        const tables = [
            createUsersTable,
            createSecurityLogsTable,
            createSessionsTable,
            createAuditLogsTable,
            createSecurityMetricsTable,
            createPasswordHistoryTable
        ];

        try {
            for (const tableSQL of tables) {
                await this.runQuery(tableSQL);
            }
            
            // Create indexes for performance
            await this.createIndexes();
            
            // Create default admin user
            await this.createDefaultUser();
            
            logger.info('All database tables created successfully');
        } catch (error) {
            logger.error('Failed to create database tables', { error: error.message });
            throw error;
        }
    }

    async createIndexes() {
        const indexes = [
            'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
            'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
            'CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_security_logs_event_type ON security_logs(event_type)',
            'CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)',
            'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)'
        ];

        for (const indexSQL of indexes) {
            await this.runQuery(indexSQL);
        }

        logger.info('Database indexes created successfully');
    }

    async createDefaultUser() {
        try {
            // Check if admin user already exists
            const existingAdmin = await this.getQuery(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                ['admin', 'admin@secureapp.com']
            );

            if (!existingAdmin) {
                const adminPassword = 'SecureAdmin123!';
                const hashedPassword = await bcrypt.hash(adminPassword, 12);

                await this.runQuery(`
                    INSERT INTO users (
                        username, email, password_hash, profile_info, 
                        is_admin, is_active, email_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [
                    'admin',
                    'admin@secureapp.com',
                    hashedPassword,
                    'Default admin user for secure production application',
                    1,
                    1,
                    1
                ]);

                logger.info('Default admin user created', {
                    username: 'admin',
                    email: 'admin@secureapp.com'
                });

                console.log('🔑 Default Admin Credentials:');
                console.log('   Username: admin');
                console.log('   Password: SecureAdmin123!');
                console.log('   Email: admin@secureapp.com');
            }

            // Create test user
            const existingTest = await this.getQuery(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                ['testuser', 'test@secureapp.com']
            );

            if (!existingTest) {
                const testPassword = 'TestUser123!';
                const hashedPassword = await bcrypt.hash(testPassword, 12);

                await this.runQuery(`
                    INSERT INTO users (
                        username, email, password_hash, profile_info, 
                        is_admin, is_active, email_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [
                    'testuser',
                    'test@secureapp.com',
                    hashedPassword,
                    'Test user for demonstration purposes',
                    0,
                    1,
                    1
                ]);

                logger.info('Test user created', {
                    username: 'testuser',
                    email: 'test@secureapp.com'
                });

                console.log('👤 Test User Credentials:');
                console.log('   Username: testuser');
                console.log('   Password: TestUser123!');
                console.log('   Email: test@secureapp.com');
            }

        } catch (error) {
            logger.error('Failed to create default users', { error: error.message });
        }
    }

    async runQuery(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    logger.error('Database query failed', { 
                        sql: sql.substring(0, 100), 
                        error: err.message 
                    });
                    reject(err);
                } else {
                    resolve({ id: this.lastID, changes: this.changes });
                }
            });
        });
    }

    async getQuery(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) {
                    logger.error('Database get query failed', { 
                        sql: sql.substring(0, 100), 
                        error: err.message 
                    });
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    async allQuery(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    logger.error('Database all query failed', { 
                        sql: sql.substring(0, 100), 
                        error: err.message 
                    });
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    async close() {
        return new Promise((resolve, reject) => {
            if (this.db) {
                this.db.close((err) => {
                    if (err) {
                        logger.error('Failed to close database', { error: err.message });
                        reject(err);
                    } else {
                        logger.info('Database connection closed');
                        resolve();
                    }
                });
            } else {
                resolve();
            }
        });
    }

    getDatabase() {
        return this.db;
    }
}

module.exports = new Database();
