const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const SECURITY_CONFIG = require('./security-config');

const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        }
    }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS || ['http://localhost:3000', 'https://yourdomain.com'],
    credentials: true
}));

app.use(express.json({ limit: '10kb' }));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: SECURITY_CONFIG.RATE_LIMIT.LOGIN_WINDOW,
    max: SECURITY_CONFIG.RATE_LIMIT.LOGIN_ATTEMPTS,
    message: { error: 'Too many authentication attempts, please try again later.' }
});

const apiLimiter = rateLimit({
    windowMs: SECURITY_CONFIG.RATE_LIMIT.API_WINDOW,
    max: SECURITY_CONFIG.RATE_LIMIT.API_REQUESTS,
    message: { error: 'Too many requests, please slow down.' }
});

// In-memory storage (replace with database in production)
const users = new Map();
const sessions = new Map();
const failedAttempts = new Map();
const auditLog = [];

// Utility functions
function generateId() {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

function logActivity(type, userId, ip, details) {
    const log = {
        id: generateId(),
        type,
        userId,
        ip,
        timestamp: new Date().toISOString(),
        details
    };
    auditLog.push(log);
    console.log(`[AUDIT] ${type}: ${userId} - ${details}`);
}

function validatePassword(password) {
    const requirements = SECURITY_CONFIG.PASSWORD;
    
    if (password.length < requirements.MIN_LENGTH) return false;
    if (requirements.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) return false;
    if (requirements.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) return false;
    if (requirements.REQUIRE_NUMBERS && !/\d/.test(password)) return false;
    if (requirements.REQUIRE_SYMBOLS && !new RegExp(`[${requirements.SYMBOLS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`).test(password)) return false;
    
    return true;
}

function isAccountLocked(email) {
    const attempts = failedAttempts.get(email);
    if (!attempts) return false;
    
    if (attempts.count >= SECURITY_CONFIG.PASSWORD.MAX_ATTEMPTS) {
        const timeSinceLastAttempt = Date.now() - attempts.lastAttempt;
        if (timeSinceLastAttempt < SECURITY_CONFIG.PASSWORD.LOCKOUT_TIME) {
            return true;
        } else {
            failedAttempts.delete(email);
            return false;
        }
    }
    return false;
}

// Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, SECURITY_CONFIG.ENCRYPTION.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Check if session is still valid
        const session = sessions.get(user.sessionId);
        if (!session || session.expires < Date.now()) {
            return res.status(403).json({ error: 'Session expired' });
        }
        
        req.user = user;
        next();
    });
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.user && req.user.role === role) {
            next();
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    };
}

// Routes
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { email, password, firstName, lastName, company, role } = req.body;

        // Validation
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ 
                error: `Password must be at least ${SECURITY_CONFIG.PASSWORD.MIN_LENGTH} characters long and include uppercase, lowercase, numbers, and symbols` 
            });
        }

        if (users.has(email)) {
            return res.status(409).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SECURITY_CONFIG.ENCRYPTION.SALT_ROUNDS);
        
        // Create user
        const userId = generateId();
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
            isLocked: false
        };

        users.set(email, user);
        
        // Create verification token
        const verificationToken = jwt.sign(
            { userId, email, type: 'verification' },
            SECURITY_CONFIG.ENCRYPTION.JWT_SECRET,
            { expiresIn: '24h' }
        );

        logActivity('REGISTER', userId, req.ip, `New user registered: ${email}`);

        res.status(201).json({ 
            message: 'Registration successful. Please check your email for verification.',
            userId,
            verificationToken
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password, twoFactorCode } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Check if account is locked
        if (isAccountLocked(email)) {
            return res.status(423).json({ error: 'Account temporarily locked due to too many failed attempts' });
        }

        const user = users.get(email);
        if (!user) {
            logActivity('FAILED_LOGIN', 'unknown', req.ip, `Failed login attempt for: ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            // Track failed attempts
            const attempts = failedAttempts.get(email) || { count: 0, lastAttempt: 0 };
            attempts.count++;
            attempts.lastAttempt = Date.now();
            failedAttempts.set(email, attempts);

            logActivity('FAILED_LOGIN', user.id, req.ip, `Failed password attempt for: ${email}`);
            
            return res.status(401).json({ 
                error: 'Invalid credentials',
                remainingAttempts: SECURITY_CONFIG.PASSWORD.MAX_ATTEMPTS - attempts.count
            });
        }

        // Clear failed attempts on successful login
        failedAttempts.delete(email);

        // Create session
        const sessionId = generateId();
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
        const userSessions = Array.from(sessions.values()).filter(s => s.userId === user.id);
        if (userSessions.length >= SECURITY_CONFIG.SESSION.MAX_SESSIONS) {
            // Remove oldest session
            const oldestSession = userSessions.sort((a, b) => a.createdAt - b.createdAt)[0];
            sessions.delete(oldestSession.id);
        }

        sessions.set(sessionId, session);

        // Update user
        user.lastLogin = new Date().toISOString();
        user.loginAttempts = 0;
        users.set(email, user);

        // Generate tokens
        const accessToken = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                role: user.role,
                sessionId 
            },
            SECURITY_CONFIG.ENCRYPTION.JWT_SECRET,
            { expiresIn: SECURITY_CONFIG.ENCRYPTION.JWT_EXPIRES }
        );

        const refreshToken = jwt.sign(
            { userId: user.id, sessionId, type: 'refresh' },
            SECURITY_CONFIG.ENCRYPTION.JWT_SECRET,
            { expiresIn: '7d' }
        );

        logActivity('LOGIN', user.id, req.ip, `Successful login from: ${req.ip}`);

        res.json({
            message: 'Login successful',
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                company: user.company
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/refresh', (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
    }

    jwt.verify(refreshToken, SECURITY_CONFIG.ENCRYPTION.JWT_SECRET, (err, decoded) => {
        if (err || decoded.type !== 'refresh') {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const session = sessions.get(decoded.sessionId);
        if (!session || session.expires < Date.now()) {
            return res.status(403).json({ error: 'Session expired' });
        }

        // Update session
        session.lastActivity = Date.now();
        sessions.set(decoded.sessionId, session);

        const newAccessToken = jwt.sign(
            { 
                userId: decoded.userId, 
                email: decoded.email, 
                role: decoded.role,
                sessionId: decoded.sessionId 
            },
            SECURITY_CONFIG.ENCRYPTION.JWT_SECRET,
            { expiresIn: SECURITY_CONFIG.ENCRYPTION.JWT_EXPIRES }
        );

        res.json({ accessToken: newAccessToken });
    });
});

app.post('/api/logout', authenticateToken, (req, res) => {
    sessions.delete(req.user.sessionId);
    logActivity('LOGOUT', req.user.userId, req.ip, 'User logged out');
    res.json({ message: 'Logout successful' });
});

app.get('/api/profile', authenticateToken, (req, res) => {
    const user = Array.from(users.values()).find(u => u.id === req.user.userId);
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
        }
    });
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, company } = req.body;
        const user = Array.from(users.values()).find(u => u.id === req.user.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.company = company || user.company;
        
        users.set(user.email, user);
        logActivity('PROFILE_UPDATE', user.id, req.ip, 'Profile updated');

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = Array.from(users.values()).find(u => u.id === req.user.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Validate new password
        if (!validatePassword(newPassword)) {
            return res.status(400).json({ 
                error: `New password must be at least ${SECURITY_CONFIG.PASSWORD.MIN_LENGTH} characters long and include uppercase, lowercase, numbers, and symbols` 
            });
        }

        // Hash new password
        user.password = await bcrypt.hash(newPassword, SECURITY_CONFIG.ENCRYPTION.SALT_ROUNDS);
        users.set(user.email, user);
        
        logActivity('PASSWORD_CHANGE', user.id, req.ip, 'Password changed successfully');

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
    const allUsers = Array.from(users.values()).map(user => ({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        company: user.company,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        isVerified: user.isVerified
    }));
    
    res.json({ users: allUsers });
});

app.get('/api/admin/audit', authenticateToken, requireRole('admin'), (req, res) => {
    res.json({ auditLog });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Bedusec Mega Organization Server running on port ${PORT}`);
    console.log(`🔒 Security features enabled:`);
    console.log(`   - Password requirements: ${SECURITY_CONFIG.PASSWORD.MIN_LENGTH}+ chars`);
    console.log(`   - Rate limiting: ${SECURITY_CONFIG.RATE_LIMIT.LOGIN_ATTEMPTS} attempts per ${SECURITY_CONFIG.RATE_LIMIT.LOGIN_WINDOW/60000}min`);
    console.log(`   - Session timeout: ${SECURITY_CONFIG.SESSION.TIMEOUT/3600000}h`);
    console.log(`   - Max sessions per user: ${SECURITY_CONFIG.SESSION.MAX_SESSIONS}`);
});
