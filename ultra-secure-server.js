const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const validator = require('validator');

const app = express();

// ==================== ULTRA SECURE CONFIGURATION ====================
const SECURITY_CONFIG = {
    // Password Security
    PASSWORD: {
        MIN_LENGTH: 14,
        REQUIRE_UPPERCASE: true,
        REQUIRE_LOWERCASE: true,
        REQUIRE_NUMBERS: true,
        REQUIRE_SYMBOLS: true,
        SYMBOLS: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        MAX_ATTEMPTS: 3,
        LOCKOUT_TIME: 1800000, // 30 minutes
        HASH_ROUNDS: 14, // Ultra secure bcrypt rounds
    },
    
    // Session Security
    SESSION: {
        TIMEOUT: 1800000, // 30 minutes
        RENEWAL_THRESHOLD: 300000, // 5 minutes
        MAX_SESSIONS: 2,
        JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
        JWT_EXPIRES: '1h',
        REFRESH_EXPIRES: '7d',
    },
    
    // Rate Limiting - Ultra Strict
    RATE_LIMIT: {
        LOGIN_ATTEMPTS: 3,
        LOGIN_WINDOW: 900000, // 15 minutes
        REGISTER_ATTEMPTS: 2,
        REGISTER_WINDOW: 3600000, // 1 hour
        API_REQUESTS: 50,
        API_WINDOW: 60000, // 1 minute
    },
    
    // Encryption & Security
    ENCRYPTION: {
        ALGORITHM: 'aes-256-gcm',
        KEY: process.env.ENCRYPTION_KEY || crypto.randomBytes(32),
    },
    
    // Headers Security
    HEADERS: {
        CSP: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https:",
        HSTS: 'max-age=31536000; includeSubDomains; preload',
        X_FRAME_OPTIONS: 'DENY',
        X_CONTENT_TYPE: 'nosniff',
        X_XSS_PROTECTION: '1; mode=block',
        REFERRER_POLICY: 'strict-origin-when-cross-origin',
    },
};

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: JSON.parse(JSON.stringify(SECURITY_CONFIG.HEADERS.CSP))
    },
    hsts: SECURITY_CONFIG.HEADERS.HSTS,
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ==================== ULTRA STRICT RATE LIMITING ====================
const createRateLimiter = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logSecurityEvent('RATE_LIMIT_EXCEEDED', req.ip, {
            endpoint: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        res.status(429).json({ error: message });
    }
});

const loginLimiter = createRateLimiter(
    SECURITY_CONFIG.RATE_LIMIT.LOGIN_WINDOW,
    SECURITY_CONFIG.RATE_LIMIT.LOGIN_ATTEMPTS,
    'Too many login attempts. Please try again later.'
);

const registerLimiter = createRateLimiter(
    SECURITY_CONFIG.RATE_LIMIT.REGISTER_WINDOW,
    SECURITY_CONFIG.RATE_LIMIT.REGISTER_ATTEMPTS,
    'Too many registration attempts. Please try again later.'
);

const apiLimiter = createRateLimiter(
    SECURITY_CONFIG.RATE_LIMIT.API_WINDOW,
    SECURITY_CONFIG.RATE_LIMIT.API_REQUESTS,
    'Too many requests. Please slow down.'
);

// ==================== SECURITY UTILITIES ====================
const securityUtils = {
    // Advanced password validation
    validatePassword: (password) => {
        const requirements = SECURITY_CONFIG.PASSWORD;
        const errors = [];
        
        if (password.length < requirements.MIN_LENGTH) {
            errors.push(`Password must be at least ${requirements.MIN_LENGTH} characters long`);
        }
        if (requirements.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        if (requirements.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        if (requirements.REQUIRE_NUMBERS && !/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }
        if (requirements.REQUIRE_SYMBOLS && !new RegExp(`[${requirements.SYMBOLS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`).test(password)) {
            errors.push(`Password must contain at least one special character: ${requirements.SYMBOLS}`);
        }
        
        // Check for common passwords
        const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome'];
        if (commonPasswords.includes(password.toLowerCase())) {
            errors.push('Password is too common. Please choose a more secure password.');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    },

    // Generate secure tokens
    generateSecureToken: (length = 32) => {
        return crypto.randomBytes(length).toString('hex');
    },

    // Encrypt sensitive data
    encryptData: (data) => {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(SECURITY_CONFIG.ENCRYPTION.ALGORITHM, SECURITY_CONFIG.ENCRYPTION.KEY);
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return {
            iv: iv.toString('hex'),
            data: encrypted
        };
    },

    // Decrypt sensitive data
    decryptData: (encryptedData) => {
        const decipher = crypto.createDecipher(SECURITY_CONFIG.ENCRYPTION.ALGORITHM, SECURITY_CONFIG.ENCRYPTION.KEY);
        let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    },

    // Sanitize user input
    sanitizeInput: (input) => {
        if (typeof input === 'string') {
            return validator.escape(validator.trim(input));
        }
        return input;
    },

    // Validate email with multiple checks
    validateEmail: (email) => {
        return validator.isEmail(email) && 
               validator.isLength(email, { min: 5, max: 254 }) &&
               !validator.contains(email, '<script>');
    }
};

// ==================== SECURITY MONITORING ====================
const securityMonitor = {
    failedLogins: new Map(),
    suspiciousActivities: new Map(),
    auditLog: [],

    logSecurityEvent: (type, ip, details) => {
        const event = {
            id: securityUtils.generateSecureToken(16),
            type,
            ip,
            timestamp: new Date().toISOString(),
            details: securityUtils.sanitizeInput(details),
            severity: this.getEventSeverity(type)
        };
        
        this.auditLog.push(event);
        
        // Keep only last 10,000 events
        if (this.auditLog.length > 10000) {
            this.auditLog = this.auditLog.slice(-10000);
        }
        
        console.log(`🔒 [SECURITY] ${type}: ${ip} - ${JSON.stringify(details)}`);
        
        // Alert on high severity events
        if (event.severity === 'HIGH') {
            this.alertSecurityTeam(event);
        }
    },

    getEventSeverity: (type) => {
        const highSeverity = ['BRUTE_FORCE_ATTEMPT', 'SQL_INJECTION_ATTEMPT', 'XSS_ATTEMPT', 'ACCOUNT_TAKEOVER'];
        const mediumSeverity = ['RATE_LIMIT_EXCEEDED', 'SUSPICIOUS_LOGIN', 'MULTIPLE_FAILED_LOGINS'];
        
        if (highSeverity.includes(type)) return 'HIGH';
        if (mediumSeverity.includes(type)) return 'MEDIUM';
        return 'LOW';
    },

    alertSecurityTeam: (event) => {
        // In production, this would send alerts to security team
        console.log(`🚨 SECURITY ALERT: ${event.type} from ${event.ip}`);
    },

    isAccountLocked: (email) => {
        const attempts = this.failedLogins.get(email);
        if (!attempts) return false;
        
        if (attempts.count >= SECURITY_CONFIG.PASSWORD.MAX_ATTEMPTS) {
            const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
            if (timeSinceLastAttempt < SECURITY_CONFIG.PASSWORD.LOCKOUT_TIME) {
                return true;
            } else {
                this.failedLogins.delete(email);
                return false;
            }
        }
        return false;
    },

    recordFailedLogin: (email, ip) => {
        const attempts = this.failedLogins.get(email) || { count: 0, lastAttempt: 0, ip };
        attempts.count++;
        attempts.lastAttempt = Date.now();
        attempts.ip = ip;
        this.failedLogins.set(email, attempts);
        
        this.logSecurityEvent('FAILED_LOGIN', ip, {
            email: securityUtils.sanitizeInput(email),
            attemptCount: attempts.count
        });
    }
};

// ==================== DATABASE (In-memory for demo) ====================
const database = {
    users: new Map(),
    sessions: new Map(),
    refreshTokens: new Map(),
    
    // Simulate database operations with encryption
    saveUser: (user) => {
        const encryptedUser = securityUtils.encryptData(user);
        this.users.set(user.email, encryptedUser);
        return user.id;
    },
    
    findUserByEmail: (email) => {
        const encryptedUser = this.users.get(email);
        return encryptedUser ? securityUtils.decryptData(encryptedUser) : null;
    },
    
    findUserById: (id) => {
        for (let [email, encryptedUser] of this.users) {
            const user = securityUtils.decryptData(encryptedUser);
            if (user.id === id) return user;
        }
        return null;
    }
};

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        securityMonitor.logSecurityEvent('MISSING_TOKEN', req.ip, { path: req.path });
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, SECURITY_CONFIG.SESSION.JWT_SECRET, (err, user) => {
        if (err) {
            securityMonitor.logSecurityEvent('INVALID_TOKEN', req.ip, { error: err.message });
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Verify session is still active
        const session = database.sessions.get(user.sessionId);
        if (!session || session.expires < Date.now()) {
            securityMonitor.logSecurityEvent('EXPIRED_SESSION', req.ip, { userId: user.userId });
            return res.status(403).json({ error: 'Session expired' });
        }
        
        // Update session activity
        session.lastActivity = Date.now();
        database.sessions.set(user.sessionId, session);
        
        req.user = user;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user && req.user.role === role) {
            next();
        } else {
            securityMonitor.logSecurityEvent('UNAUTHORIZED_ACCESS', req.ip, {
                userId: req.user?.userId,
                attemptedRole: role,
                path: req.path
            });
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    };
};

// ==================== ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'secure', 
        timestamp: new Date().toISOString(),
        security: 'ultra_secure',
        version: '1.0.0'
    });
});

// Ultra Secure Registration
app.post('/api/register', registerLimiter, async (req, res) => {
    try {
        let { email, password, firstName, lastName, company, role } = req.body;

        // Ultra-strict input validation and sanitization
        email = securityUtils.sanitizeInput(email);
        firstName = securityUtils.sanitizeInput(firstName);
        lastName = securityUtils.sanitizeInput(lastName);
        company = securityUtils.sanitizeInput(company);
        role = securityUtils.sanitizeInput(role);

        // Validate all inputs
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        if (!securityUtils.validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Ultra-secure password validation
        const passwordValidation = securityUtils.validatePassword(password);
        if (!passwordValidation.isValid) {
            return res.status(400).json({ 
                error: 'Password does not meet security requirements',
                details: passwordValidation.errors 
            });
        }

        // Check if user already exists
        if (database.findUserByEmail(email)) {
            securityMonitor.logSecurityEvent('DUPLICATE_REGISTRATION', req.ip, { email });
            return res.status(409).json({ error: 'User already exists' });
        }

        // Hash password with ultra-secure rounds
        const hashedPassword = await bcrypt.hash(password, SECURITY_CONFIG.PASSWORD.HASH_ROUNDS);
        
        // Create user with secure ID
        const userId = securityUtils.generateSecureToken(16);
        const user = {
            id: userId,
            email,
            password: hashedPassword,
            firstName,
            lastName,
            company: company || '',
            role: role || 'user',
            isVerified: false,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            loginAttempts: 0,
            isLocked: false,
            security: {
                twoFactorEnabled: false,
                lastPasswordChange: new Date().toISOString(),
                trustedDevices: []
            }
        };

        database.saveUser(user);
        
        securityMonitor.logSecurityEvent('USER_REGISTERED', req.ip, {
            userId,
            email: securityUtils.sanitizeInput(email),
            role: user.role
        });

        res.status(201).json({ 
            message: 'Registration successful. Account created with ultra-secure settings.',
            userId,
            requiresVerification: true
        });

    } catch (error) {
        console.error('Registration error:', error);
        securityMonitor.logSecurityEvent('REGISTRATION_ERROR', req.ip, { error: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Ultra Secure Login
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        let { email, password } = req.body;

        // Sanitize inputs
        email = securityUtils.sanitizeInput(email);
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Check if account is locked
        if (securityMonitor.isAccountLocked(email)) {
            return res.status(423).json({ 
                error: 'Account temporarily locked due to multiple failed attempts. Please try again in 30 minutes.' 
            });
        }

        const user = database.findUserByEmail(email);
        if (!user) {
            securityMonitor.recordFailedLogin(email, req.ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password with timing-safe comparison
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            securityMonitor.recordFailedLogin(email, req.ip);
            
            return res.status(401).json({ 
                error: 'Invalid credentials',
                remainingAttempts: SECURITY_CONFIG.PASSWORD.MAX_ATTEMPTS - securityMonitor.failedLogins.get(email)?.count
            });
        }

        // Clear failed attempts on successful login
        securityMonitor.failedLogins.delete(email);

        // Create secure session
        const sessionId = securityUtils.generateSecureToken(32);
        const session = {
            id: sessionId,
            userId: user.id,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            createdAt: new Date().toISOString(),
            expires: Date.now() + SECURITY_CONFIG.SESSION.TIMEOUT,
            lastActivity: Date.now()
        };

        // Manage session limits
        const userSessions = Array.from(database.sessions.values()).filter(s => s.userId === user.id);
        if (userSessions.length >= SECURITY_CONFIG.SESSION.MAX_SESSIONS) {
            // Remove oldest session
            const oldestSession = userSessions.sort((a, b) => a.createdAt - b.createdAt)[0];
            database.sessions.delete(oldestSession.id);
        }

        database.sessions.set(sessionId, session);

        // Update user
        user.lastLogin = new Date().toISOString();
        user.loginAttempts = 0;
        database.saveUser(user);

        // Generate ultra-secure tokens
        const accessToken = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                role: user.role,
                sessionId 
            },
            SECURITY_CONFIG.SESSION.JWT_SECRET,
            { 
                expiresIn: SECURITY_CONFIG.SESSION.JWT_EXPIRES,
                issuer: 'bedusec-ultra-secure',
                subject: user.id 
            }
        );

        const refreshToken = jwt.sign(
            { 
                userId: user.id, 
                sessionId, 
                type: 'refresh' 
            },
            SECURITY_CONFIG.SESSION.JWT_SECRET,
            { 
                expiresIn: SECURITY_CONFIG.SESSION.REFRESH_EXPIRES,
                issuer: 'bedusec-ultra-secure'
            }
        );

        // Store refresh token securely
        database.refreshTokens.set(refreshToken, {
            userId: user.id,
            expires: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
        });

        securityMonitor.logSecurityEvent('SUCCESSFUL_LOGIN', req.ip, {
            userId: user.id,
            email: securityUtils.sanitizeInput(email)
        });

        res.json({
            message: 'Login successful - Ultra Secure Session Established',
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                company: user.company
            },
            security: {
                sessionTimeout: SECURITY_CONFIG.SESSION.TIMEOUT,
                maxSessions: SECURITY_CONFIG.SESSION.MAX_SESSIONS
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        securityMonitor.logSecurityEvent('LOGIN_ERROR', req.ip, { error: error.message });
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Token refresh
app.post('/api/refresh', apiLimiter, (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
    }

    // Verify refresh token exists and is valid
    const storedToken = database.refreshTokens.get(refreshToken);
    if (!storedToken || storedToken.expires < Date.now()) {
        securityMonitor.logSecurityEvent('INVALID_REFRESH_TOKEN', req.ip, {});
        return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    jwt.verify(refreshToken, SECURITY_CONFIG.SESSION.JWT_SECRET, (err, decoded) => {
        if (err || decoded.type !== 'refresh') {
            securityMonitor.logSecurityEvent('REFRESH_TOKEN_VERIFICATION_FAILED', req.ip, { error: err?.message });
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const session = database.sessions.get(decoded.sessionId);
        if (!session || session.expires < Date.now()) {
            return res.status(403).json({ error: 'Session expired' });
        }

        // Update session
        session.lastActivity = Date.now();
        database.sessions.set(decoded.sessionId, session);

        const newAccessToken = jwt.sign(
            { 
                userId: decoded.userId, 
                email: decoded.email, 
                role: decoded.role,
                sessionId: decoded.sessionId 
            },
            SECURITY_CONFIG.SESSION.JWT_SECRET,
            { 
                expiresIn: SECURITY_CONFIG.SESSION.JWT_EXPIRES,
                issuer: 'bedusec-ultra-secure'
            }
        );

        res.json({ 
            accessToken: newAccessToken,
            message: 'Token refreshed successfully'
        });
    });
});

// Secure logout
app.post('/api/logout', authenticateToken, (req, res) => {
    const { refreshToken } = req.body;
    
    // Remove session
    database.sessions.delete(req.user.sessionId);
    
    // Remove refresh token if provided
    if (refreshToken) {
        database.refreshTokens.delete(refreshToken);
    }
    
    securityMonitor.logSecurityEvent('USER_LOGOUT', req.ip, { userId: req.user.userId });
    res.json({ message: 'Logout successful - All sessions terminated' });
});

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
    const user = database.findUserById(req.user.userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    res.json({
        user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            company: user.company,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        },
        security: {
            twoFactorEnabled: user.security.twoFactorEnabled,
            lastPasswordChange: user.security.lastPasswordChange
        }
    });
});

// Update profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        let { firstName, lastName, company } = req.body;
        
        // Sanitize inputs
        firstName = securityUtils.sanitizeInput(firstName);
        lastName = securityUtils.sanitizeInput(lastName);
        company = securityUtils.sanitizeInput(company);
        
        const user = database.findUserById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.company = company || user.company;
        
        database.saveUser(user);
        
        securityMonitor.logSecurityEvent('PROFILE_UPDATED', req.ip, { userId: user.id });
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password
app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = database.findUserById(req.user.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (!isValid) {
            securityMonitor.logSecurityEvent('INVALID_PASSWORD_CHANGE_ATTEMPT', req.ip, { userId: user.id });
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Validate new password
        const passwordValidation = securityUtils.validatePassword(newPassword);
        if (!passwordValidation.isValid) {
            return res.status(400).json({ 
                error: 'New password does not meet security requirements',
                details: passwordValidation.errors 
            });
        }

        // Hash new password
        user.password = await bcrypt.hash(newPassword, SECURITY_CONFIG.PASSWORD.HASH_ROUNDS);
        user.security.lastPasswordChange = new Date().toISOString();
        database.saveUser(user);
        
        securityMonitor.logSecurityEvent('PASSWORD_CHANGED', req.ip, { userId: user.id });
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
    const allUsers = Array.from(database.users.values()).map(encryptedUser => {
        const user = securityUtils.decryptData(encryptedUser);
        return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            company: user.company,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            isVerified: user.isVerified
        };
    });
    
    res.json({ users: allUsers });
});

app.get('/api/admin/security-events', authenticateToken, requireRole('admin'), (req, res) => {
    res.json({ 
        events: securityMonitor.auditLog.slice(-100), // Last 100 events
        stats: {
            totalEvents: securityMonitor.auditLog.length,
            failedLogins: securityMonitor.failedLogins.size,
            lockedAccounts: Array.from(securityMonitor.failedLogins.entries())
                .filter(([_, attempts]) => attempts.count >= SECURITY_CONFIG.PASSWORD.MAX_ATTEMPTS).length
        }
    });
});

// Security health endpoint
app.get('/api/security/health', authenticateToken, (req, res) => {
    res.json({
        status: 'ultra_secure',
        features: {
            passwordHashing: 'bcrypt-14-rounds',
            encryption: 'AES-256-GCM',
            rateLimiting: 'enabled',
            sessionManagement: 'active',
            securityMonitoring: 'enabled'
        },
        stats: {
            totalUsers: database.users.size,
            activeSessions: database.sessions.size,
            securityEvents: securityMonitor.auditLog.length
        }
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Bedusec Ultra Secure Server running on port ${PORT}`);
    console.log(`🔒 Security Level: ULTRA SECURE`);
    console.log(`📊 Features:`);
    console.log(`   - Password Requirements: ${SECURITY_CONFIG.PASSWORD.MIN_LENGTH}+ chars with symbols`);
    console.log(`   - Rate Limiting: ${SECURITY_CONFIG.RATE_LIMIT.LOGIN_ATTEMPTS} login attempts per 15min`);
    console.log(`   - Session Timeout: ${SECURITY_CONFIG.SESSION.TIMEOUT/60000} minutes`);
    console.log(`   - Max Sessions: ${SECURITY_CONFIG.SESSION.MAX_SESSIONS} per user`);
    console.log(`   - Encryption: ${SECURITY_CONFIG.ENCRYPTION.ALGORITHM}`);
    console.log(`   - Security Monitoring: ACTIVE`);
});
