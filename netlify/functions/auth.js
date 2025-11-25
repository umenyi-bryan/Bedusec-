// Netlify Function for Ultra Secure Authentication
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Ultra Secure Configuration
const SECURITY_CONFIG = {
    PASSWORD: {
        MIN_LENGTH: 12,
        REQUIRE_UPPERCASE: true,
        REQUIRE_LOWERCASE: true,
        REQUIRE_NUMBERS: true,
        REQUIRE_SYMBOLS: true,
        HASH_ROUNDS: 12,
    },
    JWT: {
        SECRET: process.env.JWT_SECRET || 'bedusec_ultra_secure_netlify_key_change_in_production',
        EXPIRES: '24h'
    }
};

// In-memory storage (In production, use a database like FaunaDB, MongoDB Atlas, or Supabase)
const users = new Map();
const sessions = new Map();

// Security Utilities
const securityUtils = {
    validatePassword: (password) => {
        const requirements = SECURITY_CONFIG.PASSWORD;
        const errors = [];
        
        if (password.length < requirements.MIN_LENGTH) {
            errors.push(`Password must be at least ${requirements.MIN_LENGTH} characters`);
        }
        if (requirements.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
            errors.push('Password must contain uppercase letters');
        }
        if (requirements.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
            errors.push('Password must contain lowercase letters');
        }
        if (requirements.REQUIRE_NUMBERS && !/\d/.test(password)) {
            errors.push('Password must contain numbers');
        }
        if (requirements.REQUIRE_SYMBOLS && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password)) {
            errors.push('Password must contain special characters');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    },

    generateId: () => {
        return crypto.randomBytes(16).toString('hex');
    },

    sanitizeEmail: (email) => {
        return email.toLowerCase().trim();
    }
};

exports.handler = async (event, context) => {
    // CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    try {
        const path = event.path.replace('/.netlify/functions/auth', '');
        const method = event.httpMethod;

        // Route handling
        if (method === 'POST' && path === '/register') {
            return await handleRegister(event);
        } else if (method === 'POST' && path === '/login') {
            return await handleLogin(event);
        } else if (method === 'POST' && path === '/logout') {
            return await handleLogout(event);
        } else if (method === 'GET' && path === '/profile') {
            return await handleGetProfile(event);
        } else if (method === 'POST' && path === '/refresh') {
            return await handleRefreshToken(event);
        } else {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'Endpoint not found' })
            };
        }
    } catch (error) {
        console.error('Auth function error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};

// Registration Handler
async function handleRegister(event) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const { email, password, firstName, lastName, company, role } = JSON.parse(event.body);

        // Validation
        if (!email || !password || !firstName || !lastName) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'All fields are required' })
            };
        }

        const sanitizedEmail = securityUtils.sanitizeEmail(email);

        // Password validation
        const passwordValidation = securityUtils.validatePassword(password);
        if (!passwordValidation.isValid) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Password does not meet security requirements',
                    details: passwordValidation.errors 
                })
            };
        }

        // Check if user exists
        if (users.has(sanitizedEmail)) {
            return {
                statusCode: 409,
                headers,
                body: JSON.stringify({ error: 'User already exists' })
            };
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SECURITY_CONFIG.PASSWORD.HASH_ROUNDS);
        
        // Create user
        const userId = securityUtils.generateId();
        const user = {
            id: userId,
            email: sanitizedEmail,
            password: hashedPassword,
            firstName: firstName.trim(),
            lastName: lastName.trim(),
            company: company?.trim() || '',
            role: role || 'user',
            isVerified: false,
            createdAt: new Date().toISOString(),
            lastLogin: null
        };

        users.set(sanitizedEmail, user);

        console.log(`🔐 New user registered: ${sanitizedEmail}`);

        return {
            statusCode: 201,
            headers,
            body: JSON.stringify({ 
                message: 'Registration successful! You can now login.',
                userId,
                requiresVerification: false
            })
        };

    } catch (error) {
        console.error('Registration error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Registration failed' })
        };
    }
}

// Login Handler
async function handleLogin(event) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const { email, password } = JSON.parse(event.body);

        if (!email || !password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Email and password required' })
            };
        }

        const sanitizedEmail = securityUtils.sanitizeEmail(email);
        const user = users.get(sanitizedEmail);

        if (!user) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Invalid credentials' })
            };
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Invalid credentials' })
            };
        }

        // Create session
        const sessionId = securityUtils.generateId();
        const session = {
            id: sessionId,
            userId: user.id,
            createdAt: new Date().toISOString(),
            expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        };

        sessions.set(sessionId, session);

        // Update user
        user.lastLogin = new Date().toISOString();
        users.set(sanitizedEmail, user);

        // Generate tokens
        const accessToken = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                role: user.role,
                sessionId 
            },
            SECURITY_CONFIG.JWT.SECRET,
            { expiresIn: SECURITY_CONFIG.JWT.EXPIRES }
        );

        const refreshToken = jwt.sign(
            { 
                userId: user.id, 
                sessionId, 
                type: 'refresh' 
            },
            SECURITY_CONFIG.JWT.SECRET,
            { expiresIn: '7d' }
        );

        console.log(`🔐 User logged in: ${user.email}`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                message: 'Login successful!',
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
            })
        };

    } catch (error) {
        console.error('Login error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Login failed' })
        };
    }
}

// Get Profile Handler
async function handleGetProfile(event) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const authHeader = event.headers.authorization;
        if (!authHeader) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Authorization header required' })
            };
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECURITY_CONFIG.JWT.SECRET);

        // Verify session
        const session = sessions.get(decoded.sessionId);
        if (!session || session.expires < Date.now()) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Session expired' })
            };
        }

        // Find user
        const user = Array.from(users.values()).find(u => u.id === decoded.userId);
        if (!user) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
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
            })
        };

    } catch (error) {
        console.error('Profile error:', error);
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ error: 'Invalid token' })
        };
    }
}

// Logout Handler
async function handleLogout(event) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const authHeader = event.headers.authorization;
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, SECURITY_CONFIG.JWT.SECRET);
            sessions.delete(decoded.sessionId);
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ message: 'Logout successful' })
        };

    } catch (error) {
        console.error('Logout error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Logout failed' })
        };
    }
}

// Refresh Token Handler
async function handleRefreshToken(event) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const { refreshToken } = JSON.parse(event.body);

        if (!refreshToken) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Refresh token required' })
            };
        }

        const decoded = jwt.verify(refreshToken, SECURITY_CONFIG.JWT.SECRET);
        
        if (decoded.type !== 'refresh') {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Invalid refresh token' })
            };
        }

        // Verify session
        const session = sessions.get(decoded.sessionId);
        if (!session || session.expires < Date.now()) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: 'Session expired' })
            };
        }

        // Find user
        const user = Array.from(users.values()).find(u => u.id === decoded.userId);
        if (!user) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                role: user.role,
                sessionId: decoded.sessionId 
            },
            SECURITY_CONFIG.JWT.SECRET,
            { expiresIn: SECURITY_CONFIG.JWT.EXPIRES }
        );

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                accessToken: newAccessToken,
                message: 'Token refreshed successfully'
            })
        };

    } catch (error) {
        console.error('Token refresh error:', error);
        return {
            statusCode: 401,
            headers,
            body: JSON.stringify({ error: 'Invalid refresh token' })
        };
    }
}
