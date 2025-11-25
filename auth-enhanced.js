// Enhanced Authentication System for Bedusec Mega Organization
class AuthSystem {
    constructor() {
        this.baseURL = window.location.origin;
        this.tokenKey = 'bedusec_access_token';
        this.refreshTokenKey = 'bedusec_refresh_token';
        this.userKey = 'bedusec_user_data';
        this.init();
    }

    init() {
        this.setupInterceptors();
        this.checkTokenExpiry();
        this.setupAutoLogout();
    }

    setupInterceptors() {
        // Intercept fetch requests to add auth headers
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const [resource, config = {}] = args;
            
            // Add auth header if token exists
            const token = this.getToken();
            if (token) {
                config.headers = {
                    ...config.headers,
                    'Authorization': `Bearer ${token}`
                };
            }

            try {
                const response = await originalFetch(resource, config);
                
                // Handle token expiry
                if (response.status === 403) {
                    const refreshed = await this.refreshToken();
                    if (refreshed) {
                        // Retry original request with new token
                        const newToken = this.getToken();
                        config.headers.Authorization = `Bearer ${newToken}`;
                        return originalFetch(resource, config);
                    } else {
                        this.logout();
                        throw new Error('Session expired. Please login again.');
                    }
                }

                return response;
            } catch (error) {
                console.error('Request failed:', error);
                throw error;
            }
        };
    }

    async register(userData) {
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Registration failed');
            }

            this.showNotification('Registration successful! Please check your email for verification.', 'success');
            return data;
        } catch (error) {
            this.showNotification(error.message, 'error');
            throw error;
        }
    }

    async login(credentials) {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentials)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store tokens and user data
            this.setToken(data.accessToken);
            this.setRefreshToken(data.refreshToken);
            this.setUserData(data.user);

            this.showNotification('Login successful!', 'success');
            
            // Redirect to dashboard or intended page
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 1000);

            return data;
        } catch (error) {
            this.showNotification(error.message, 'error');
            throw error;
        }
    }

    async logout() {
        try {
            const token = this.getToken();
            if (token) {
                await fetch('/api/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearAuthData();
            window.location.href = '/login.html';
        }
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
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }
        
        return false;
    }

    async changePassword(passwordData) {
        try {
            const response = await fetch('/api/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getToken()}`
                },
                body: JSON.stringify(passwordData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Password change failed');
            }

            this.showNotification('Password changed successfully!', 'success');
            return data;
        } catch (error) {
            this.showNotification(error.message, 'error');
            throw error;
        }
    }

    async updateProfile(profileData) {
        try {
            const response = await fetch('/api/profile', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getToken()}`
                },
                body: JSON.stringify(profileData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Profile update failed');
            }

            // Update stored user data
            const currentUser = this.getUserData();
            this.setUserData({ ...currentUser, ...profileData });

            this.showNotification('Profile updated successfully!', 'success');
            return data;
        } catch (error) {
            this.showNotification(error.message, 'error');
            throw error;
        }
    }

    // Token management
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

    clearAuthData() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshTokenKey);
        localStorage.removeItem(this.userKey);
    }

    isAuthenticated() {
        const token = this.getToken();
        const user = this.getUserData();
        return !!(token && user);
    }

    // Security utilities
    checkTokenExpiry() {
        const token = this.getToken();
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                const expiry = payload.exp * 1000;
                const now = Date.now();
                
                if (expiry - now < 300000) { // 5 minutes
                    this.refreshToken();
                }
            } catch (error) {
                console.error('Token validation error:', error);
            }
        }
    }

    setupAutoLogout() {
        let inactivityTimer;
        const logoutTime = 60 * 60 * 1000; // 1 hour

        const resetTimer = () => {
            clearTimeout(inactivityTimer);
            inactivityTimer = setTimeout(() => {
                if (this.isAuthenticated()) {
                    this.showNotification('Session expired due to inactivity', 'warning');
                    this.logout();
                }
            }, logoutTime);
        };

        // Reset timer on user activity
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetTimer, false);
        });

        resetTimer();
    }

    // Password strength checker
    checkPasswordStrength(password) {
        const requirements = {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /\d/.test(password),
            symbols: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password)
        };

        const score = Object.values(requirements).filter(Boolean).length;
        let strength = 'weak';
        let message = '';

        if (score === 5) {
            strength = 'very-strong';
            message = 'Excellent! Your password is very strong.';
        } else if (score >= 4) {
            strength = 'strong';
            message = 'Good! Your password is strong.';
        } else if (score >= 3) {
            strength = 'medium';
            message = 'Fair. Consider adding more complexity.';
        } else {
            strength = 'weak';
            message = 'Weak. Please improve your password strength.';
        }

        return { strength, message, requirements };
    }

    // Security notifications
    showNotification(message, type = 'info') {
        // Remove existing notifications
        const existing = document.querySelector('.security-notification');
        if (existing) existing.remove();

        const notification = document.createElement('div');
        notification.className = `security-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    // Session security check
    async validateSession() {
        if (!this.isAuthenticated()) return false;

        try {
            const response = await fetch('/api/profile', {
                headers: {
                    'Authorization': `Bearer ${this.getToken()}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.setUserData(data.user);
                return true;
            } else {
                this.logout();
                return false;
            }
        } catch (error) {
            console.error('Session validation error:', error);
            return false;
        }
    }
}

// Initialize auth system
const authSystem = new AuthSystem();

// Password visibility toggle
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.parentElement.querySelector('.password-toggle i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// Real-time password strength indicator
function updatePasswordStrength(password, strengthElement) {
    const strength = authSystem.checkPasswordStrength(password);
    
    strengthElement.className = `password-strength ${strength.strength}`;
    strengthElement.innerHTML = `
        <div class="strength-bar">
            <div class="strength-fill ${strength.strength}"></div>
        </div>
        <div class="strength-text">${strength.message}</div>
        <div class="strength-requirements">
            ${Object.entries(strength.requirements).map(([key, met]) => `
                <div class="requirement ${met ? 'met' : 'unmet'}">
                    <i class="fas fa-${met ? 'check' : 'times'}"></i>
                    ${key.charAt(0).toUpperCase() + key.slice(1)}
                </div>
            `).join('')}
        </div>
    `;
}

// Form validation
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function validateForm(formData) {
    const errors = {};

    if (!formData.email || !validateEmail(formData.email)) {
        errors.email = 'Please enter a valid email address';
    }

    if (!formData.password) {
        errors.password = 'Password is required';
    }

    if (formData.confirmPassword && formData.password !== formData.confirmPassword) {
        errors.confirmPassword = 'Passwords do not match';
    }

    if (!formData.firstName) {
        errors.firstName = 'First name is required';
    }

    if (!formData.lastName) {
        errors.lastName = 'Last name is required';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
}

// Protected route check
function requireAuth() {
    if (!authSystem.isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

// Admin route check
function requireAdmin() {
    if (!authSystem.isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }

    const user = authSystem.getUserData();
    if (user.role !== 'admin') {
        window.location.href = '/dashboard.html';
        return false;
    }

    return true;
}
