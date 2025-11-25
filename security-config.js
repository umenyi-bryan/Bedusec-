// Enhanced Security Configuration
const SECURITY_CONFIG = {
    // Password requirements
    PASSWORD: {
        MIN_LENGTH: 12,
        REQUIRE_UPPERCASE: true,
        REQUIRE_LOWERCASE: true,
        REQUIRE_NUMBERS: true,
        REQUIRE_SYMBOLS: true,
        SYMBOLS: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        MAX_ATTEMPTS: 5,
        LOCKOUT_TIME: 900000, // 15 minutes
    },
    
    // Session security
    SESSION: {
        TIMEOUT: 3600000, // 1 hour
        RENEWAL_THRESHOLD: 300000, // 5 minutes
        MAX_SESSIONS: 3,
    },
    
    // Rate limiting
    RATE_LIMIT: {
        LOGIN_ATTEMPTS: 5,
        LOGIN_WINDOW: 900000, // 15 minutes
        API_REQUESTS: 100,
        API_WINDOW: 60000, // 1 minute
    },
    
    // Encryption
    ENCRYPTION: {
        SALT_ROUNDS: 12,
        JWT_SECRET: process.env.JWT_SECRET || 'bedusec_mega_org_2024_secure_key_change_in_production',
        JWT_EXPIRES: '24h',
    },
    
    // CORS and headers
    HEADERS: {
        CSP: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'",
        HSTS: 'max-age=31536000; includeSubDomains',
        X_FRAME_OPTIONS: 'DENY',
        X_CONTENT_TYPE: 'nosniff',
        X_XSS_PROTECTION: '1; mode=block',
    },
    
    // Database security
    DATABASE: {
        BACKUP_INTERVAL: 86400000, // 24 hours
        ENCRYPT_DATA: true,
        QUERY_TIMEOUT: 10000,
    },
    
    // Monitoring
    MONITORING: {
        LOG_FAILED_LOGINS: true,
        LOG_SUSPICIOUS_ACTIVITY: true,
        ALERT_ON_BREACH: true,
    }
};

module.exports = SECURITY_CONFIG;
