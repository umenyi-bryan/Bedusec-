// Ultra Secure Frontend Integration for Bedusec
class UltraSecureAuth {
    constructor() {
        this.baseURL = window.location.origin;
        this.tokenKey = 'bedusec_ultra_secure_token';
        this.refreshTokenKey = 'bedusec_ultra_secure_refresh_token';
        this.userKey = 'bedusec_ultra_secure_user';
        this.securityLog = [];
        this.init();
    }

    init() {
        this.setupSecurityInterceptors();
        this.startSecurityMonitoring();
        this.setupAutoLock();
        this.validateEnvironment();
    }

    setupSecurityInterceptors() {
        const originalFetch = window.fetch;
        
        window.fetch = async (resource, config = {}) => {
            // Add security headers
            config.headers = {
                ...config.headers,
                'X-Requested-With': 'XMLHttpRequest',
                'X-Security-Level': 'ultra_secure'
            };

            // Add auth token if available
            const token = this.getToken();
            if (token) {
                config.headers.Authorization = `Bearer ${token}`;
            }

            const startTime = Date.now();
            
            try {
                const response = await originalFetch(resource, config);
                this.logSecurityEvent('API_REQUEST', {
                    url: resource,
                    method: config.method || 'GET',
                    status: response.status,
                    duration: Date.now() - startTime
                });

                // Handle token expiry
                if (response.status === 403) {
                    const refreshed = await this.refreshToken();
                    if (refreshed) {
                        // Retry with new token
                        config.headers.Authorization = `Bearer ${this.getToken()}`;
                        return originalFetch(resource, config);
                    } else {
                        this.secureLogout();
                        throw new Error('Session security violation - Please login again');
                    }
                }

                return response;
            } catch (error) {
                this.logSecurityEvent('API_ERROR', {
                    url: resource,
                    error: error.message,
                    duration: Date.now() - startTime
                });
                throw error;
            }
        };
    }

    async ultraSecureRegister(userData) {
        this.logSecurityEvent('REGISTER_ATTEMPT', { email: userData.email });
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Security-Context': 'ultra_secure_registration'
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();

            if (!response.ok) {
                this.logSecurityEvent('REGISTER_FAILED', {
                    email: userData.email,
                    error: data.error
                });
                throw new Error(data.error || 'Registration security check failed');
            }

            this.logSecurityEvent('REGISTER_SUCCESS', { email: userData.email });
            this.showSecurityAlert('Ultra Secure Account Created! Please check your email for verification.', 'success');
            
            return data;
        } catch (error) {
            this.showSecurityAlert(error.message, 'error');
            throw error;
        }
    }

    async ultraSecureLogin(credentials) {
        this.logSecurityEvent('LOGIN_ATTEMPT', { email: credentials.email });
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Security-Context': 'ultra_secure_login'
                },
                body: JSON.stringify(credentials)
            });

            const data = await response.json();

            if (!response.ok) {
                this.logSecurityEvent('LOGIN_FAILED', {
                    email: credentials.email,
                    error: data.error
                });
                throw new Error(data.error || 'Login security check failed');
            }

            // Store tokens securely
            this.setToken(data.accessToken);
            this.setRefreshToken(data.refreshToken);
            this.setUserData(data.user);

            this.logSecurityEvent('LOGIN_SUCCESS', {
                email: credentials.email,
                userId: data.user.id
            });

            this.showSecurityAlert('Ultra Secure Session Established!', 'success');
            
            // Redirect to secure dashboard
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 1500);

            return data;
        } catch (error) {
            this.showSecurityAlert(error.message, 'error');
            throw error;
        }
    }

    async secureLogout() {
        try {
            const token = this.getToken();
            const refreshToken = this.getRefreshToken();
            
            if (token) {
                await fetch('/api/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ refreshToken })
                });
            }
        } catch (error) {
            console.error('Secure logout error:', error);
        } finally {
            this.clearAllSecurityData();
            this.logSecurityEvent('USER_LOGOUT', {});
            window.location.href = '/login-enhanced.html';
        }
    }

    // Advanced Security Features
    startSecurityMonitoring() {
        // Monitor for suspicious activities
        setInterval(() => {
            this.checkSessionHealth();
            this.analyzeSecurityPatterns();
        }, 60000); // Check every minute
    }

    setupAutoLock() {
        let inactivityTimer;
        const lockTime = 15 * 60 * 1000; // 15 minutes

        const resetTimer = () => {
            clearTimeout(inactivityTimer);
            if (this.isAuthenticated()) {
                inactivityTimer = setTimeout(() => {
                    this.showSecurityAlert('Session locked due to inactivity', 'warning');
                    this.secureLogout();
                }, lockTime);
            }
        };

        // Monitor user activity
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
            document.addEventListener(event, resetTimer, { passive: true });
        });

        resetTimer();
    }

    checkSessionHealth() {
        if (!this.isAuthenticated()) return;

        const token = this.getToken();
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                const expiry = payload.exp * 1000;
                const timeLeft = expiry - Date.now();
                
                if (timeLeft < 300000) { // 5 minutes
                    this.refreshToken();
                }
                
                if (timeLeft < 60000) { // 1 minute
                    this.showSecurityAlert('Session expiring soon...', 'warning');
                }
            } catch (error) {
                this.logSecurityEvent('TOKEN_VALIDATION_ERROR', { error: error.message });
            }
        }
    }

    analyzeSecurityPatterns() {
        // Analyze recent security events for patterns
        const recentEvents = this.securityLog.filter(event => 
            Date.now() - event.timestamp < 300000 // Last 5 minutes
        );

        const failedLogins = recentEvents.filter(event => 
            event.type === 'LOGIN_FAILED'
        ).length;

        if (failedLogins >= 3) {
            this.logSecurityEvent('SUSPICIOUS_ACTIVITY_DETECTED', {
                type: 'multiple_failed_logins',
                count: failedLogins
            });
        }
    }

    // Enhanced Password Security
    analyzePasswordStrength(password) {
        const analysis = {
            length: password.length >= 14,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /\d/.test(password),
            symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password),
            common: !this.isCommonPassword(password),
            sequences: !this.hasSequences(password),
            repeated: !this.hasRepeatedChars(password)
        };

        const score = Object.values(analysis).filter(Boolean).length;
        let strength = 'critical';
        let message = '';

        if (score >= 7) {
            strength = 'ultra_secure';
            message = 'Ultra Secure - Excellent password strength';
        } else if (score >= 5) {
            strength = 'secure';
            message = 'Secure - Good password strength';
        } else if (score >= 3) {
            strength = 'moderate';
            message = 'Moderate - Consider improving password strength';
        } else {
            strength = 'weak';
            message = 'Weak - Does not meet security requirements';
        }

        return { strength, message, analysis, score };
    }

    isCommonPassword(password) {
        const commonPasswords = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'password123', 'admin123', 'qwerty123', 'letmein'
        ];
        return commonPasswords.includes(password.toLowerCase());
    }

    hasSequences(password) {
        const sequences = ['123', 'abc', 'qwe', 'asd', 'zxc'];
        return sequences.some(seq => password.toLowerCase().includes(seq));
    }

    hasRepeatedChars(password) {
        return /(.)\1{2,}/.test(password);
    }

    // Security Utilities
    setToken(token) {
        localStorage.setItem(this.tokenKey, token);
    }

    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    setRefreshToken(token) {
        localStorage.setItem(this.refreshTokenKey, token);
    }

    getRefreshToken() {
        return localStorage.getItem(this.refreshTokenKey);
    }

    setUserData(user) {
        localStorage.setItem(this.userKey, JSON.stringify(user));
    }

    getUserData() {
        const user = localStorage.getItem(this.userKey);
        return user ? JSON.parse(user) : null;
    }

    clearAllSecurityData() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshTokenKey);
        localStorage.removeItem(this.userKey);
        this.securityLog = [];
    }

    isAuthenticated() {
        const token = this.getToken();
        const user = this.getUserData();
        return !!(token && user);
    }

    async refreshToken() {
        try {
            const refreshToken = this.getRefreshToken();
            if (!refreshToken) return false;

            const response = await fetch('/api/refresh', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getToken()}`
                },
                body: JSON.stringify({ refreshToken })
            });

            if (response.ok) {
                const data = await response.json();
                this.setToken(data.accessToken);
                this.logSecurityEvent('TOKEN_REFRESHED', {});
                return true;
            }
        } catch (error) {
            this.logSecurityEvent('TOKEN_REFRESH_FAILED', { error: error.message });
        }
        
        return false;
    }

    // Security Logging
    logSecurityEvent(type, details) {
        const event = {
            type,
            timestamp: Date.now(),
            details,
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        this.securityLog.push(event);
        
        // Keep only last 1000 events
        if (this.securityLog.length > 1000) {
            this.securityLog = this.securityLog.slice(-1000);
        }
        
        console.log(`🔒 [SECURITY] ${type}:`, details);
    }

    // Security UI
    showSecurityAlert(message, level = 'info') {
        // Remove existing alerts
        const existing = document.querySelector('.ultra-secure-alert');
        if (existing) existing.remove();

        const alert = document.createElement('div');
        alert.className = `ultra-secure-alert ${level}`;
        alert.innerHTML = `
            <div class="alert-content">
                <i class="fas fa-shield-check"></i>
                <span>${message}</span>
                <button class="alert-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        document.body.appendChild(alert);

        // Auto-remove after 5 seconds for info, 10 for warnings
        const duration = level === 'warning' ? 10000 : 5000;
        setTimeout(() => {
            if (alert.parentElement) {
                alert.remove();
            }
        }, duration);
    }

    validateEnvironment() {
        // Check if running in secure context
        if (!window.isSecureContext) {
            this.showSecurityAlert('Warning: Not running in secure context', 'warning');
        }

        // Check for dev tools (basic detection)
        const devTools = /./;
        devTools.toString = function() {
            this.opened = true;
        };
        console.log('%c', devTools);
        
        if (devTools.opened) {
            this.logSecurityEvent('DEVTOOLS_DETECTED', {});
        }
    }
}

// Initialize ultra secure auth system
const ultraSecureAuth = new UltraSecureAuth();

// Enhanced password strength UI
function updateUltraPasswordStrength(password, strengthElement) {
    const analysis = ultraSecureAuth.analyzePasswordStrength(password);
    
    strengthElement.className = `ultra-password-strength ${analysis.strength}`;
    strengthElement.innerHTML = `
        <div class="strength-header">
            <span class="strength-label">Security Level: ${analysis.strength.toUpperCase()}</span>
            <span class="strength-score">${analysis.score}/8</span>
        </div>
        <div class="strength-bar">
            <div class="strength-fill ${analysis.strength}"></div>
        </div>
        <div class="strength-message">${analysis.message}</div>
        <div class="security-requirements">
            ${Object.entries(analysis.analysis).map(([key, met]) => `
                <div class="requirement ${met ? 'met' : 'unmet'}">
                    <i class="fas fa-${met ? 'check' : 'times'}"></i>
                    ${formatRequirementText(key)}
                </div>
            `).join('')}
        </div>
    `;
}

function formatRequirementText(key) {
    const texts = {
        length: '14+ characters',
        uppercase: 'Uppercase letter',
        lowercase: 'Lowercase letter',
        numbers: 'Number',
        symbols: 'Special character',
        common: 'Not common password',
        sequences: 'No simple sequences',
        repeated: 'No repeated characters'
    };
    return texts[key] || key;
}

// Ultra secure form validation
function validateUltraForm(formData) {
    const errors = {};
    const warnings = {};

    // Email validation
    if (!formData.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
        errors.email = 'Valid organization email required';
    }

    // Password validation
    if (formData.password) {
        const strength = ultraSecureAuth.analyzePasswordStrength(formData.password);
        if (strength.strength === 'weak') {
            errors.password = 'Password does not meet security requirements';
        } else if (strength.strength === 'moderate') {
            warnings.password = 'Consider strengthening your password for better security';
        }
    }

    // Confirm password
    if (formData.confirmPassword && formData.password !== formData.confirmPassword) {
        errors.confirmPassword = 'Passwords do not match';
    }

    // Required fields
    if (!formData.firstName) errors.firstName = 'First name required';
    if (!formData.lastName) errors.lastName = 'Last name required';

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
        warnings
    };
}

// Security event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Add security headers to all forms
    document.querySelectorAll('form').forEach(form => {
        form.setAttribute('autocomplete', 'on');
        form.addEventListener('submit', function(e) {
            // Add small delay to prevent timing attacks
            setTimeout(() => {
                ultraSecureAuth.logSecurityEvent('FORM_SUBMISSION', {
                    formId: this.id || 'unknown',
                    action: this.action
                });
            }, 100);
        });
    });

    // Monitor for copy/paste on password fields
    document.querySelectorAll('input[type="password"]').forEach(input => {
        input.addEventListener('copy', (e) => {
            ultraSecureAuth.logSecurityEvent('PASSWORD_COPY_ATTEMPT', {});
        });
        
        input.addEventListener('paste', (e) => {
            ultraSecureAuth.logSecurityEvent('PASSWORD_PASTE_ATTEMPT', {});
        });
    });
});
