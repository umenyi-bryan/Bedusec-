// Netlify-compatible Authentication System
class NetlifyAuth {
    constructor() {
        this.baseURL = window.location.origin;
        this.tokenKey = 'bedusec_netlify_token';
        this.refreshTokenKey = 'bedusec_netlify_refresh_token';
        this.userKey = 'bedusec_netlify_user';
        this.init();
    }

    init() {
        this.setupInterceptors();
        this.checkAuthStatus();
    }

    setupInterceptors() {
        const originalFetch = window.fetch;
        window.fetch = async (resource, config = {}) => {
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
                if (response.status === 401) {
                    const refreshed = await this.refreshToken();
                    if (refreshed) {
                        // Retry with new token
                        config.headers.Authorization = `Bearer ${this.getToken()}`;
                        return originalFetch(resource, config);
                    } else {
                        this.logout();
                        throw new Error('Session expired');
                    }
                }

                return response;
            } catch (error) {
                console.error('API Error:', error);
                throw error;
            }
        };
    }

    async register(userData) {
        try {
            this.showNotification('Creating secure account...', 'info');
            
            const response = await fetch('/.netlify/functions/auth/register', {
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

            this.showNotification('Account created successfully! You can now login.', 'success');
            return data;

        } catch (error) {
            this.showNotification(error.message, 'error');
            throw error;
        }
    }

    async login(credentials) {
        try {
            this.showNotification('Establishing secure connection...', 'info');
            
            const response = await fetch('/.netlify/functions/auth/login', {
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

            this.showNotification('Welcome back! Secure session established.', 'success');
            
            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);

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
                await fetch('/.netlify/functions/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearAuth();
            window.location.href = 'login.html';
        }
    }

    async getProfile() {
        try {
            const response = await fetch('/.netlify/functions/auth/profile', {
                headers: {
                    'Authorization': `Bearer ${this.getToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch profile');
            }

            return await response.json();
        } catch (error) {
            console.error('Profile error:', error);
            throw error;
        }
    }

    async refreshToken() {
        try {
            const refreshToken = this.getRefreshToken();
            if (!refreshToken) return false;

            const response = await fetch('/.netlify/functions/auth/refresh', {
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

    clearAuth() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshTokenKey);
        localStorage.removeItem(this.userKey);
    }

    isAuthenticated() {
        const token = this.getToken();
        const user = this.getUserData();
        return !!(token && user);
    }

    checkAuthStatus() {
        if (this.isAuthenticated()) {
            // Validate token expiry
            const token = this.getToken();
            if (token) {
                try {
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    const expiry = payload.exp * 1000;
                    if (expiry - Date.now() < 300000) { // 5 minutes
                        this.refreshToken();
                    }
                } catch (error) {
                    console.error('Token validation error:', error);
                }
            }
        }
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
            message = 'Excellent! Ultra secure password.';
        } else if (score >= 4) {
            strength = 'strong';
            message = 'Strong password. Good job!';
        } else if (score >= 3) {
            strength = 'medium';
            message = 'Moderate password. Consider adding more complexity.';
        } else {
            strength = 'weak';
            message = 'Weak password. Please improve security.';
        }

        return { strength, message, requirements };
    }

    // Notifications
    showNotification(message, type = 'info') {
        // Remove existing notifications
        const existing = document.querySelector('.auth-notification');
        if (existing) existing.remove();

        const notification = document.createElement('div');
        notification.className = `auth-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
                <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        // Add styles if not exists
        if (!document.querySelector('#auth-notification-styles')) {
            const styles = document.createElement('style');
            styles.id = 'auth-notification-styles';
            styles.textContent = `
                .auth-notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: rgba(0, 20, 0, 0.95);
                    border: 2px solid;
                    border-radius: 8px;
                    padding: 1rem;
                    max-width: 400px;
                    z-index: 10000;
                    backdrop-filter: blur(10px);
                    animation: slideInRight 0.3s ease;
                }
                .auth-notification.success { border-color: #00ff00; }
                .auth-notification.error { border-color: #ff4444; }
                .auth-notification.info { border-color: #0088ff; }
                .auth-notification.warning { border-color: #ffaa00; }
                .notification-content {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                    color: white;
                }
                .notification-close {
                    background: none;
                    border: none;
                    color: inherit;
                    cursor: pointer;
                    margin-left: auto;
                }
                @keyframes slideInRight {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `;
            document.head.appendChild(styles);
        }

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
}

// Initialize auth system
const netlifyAuth = new NetlifyAuth();

// Utility functions
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

// Real-time password strength
function updatePasswordStrength(password, strengthElement) {
    const strength = netlifyAuth.checkPasswordStrength(password);
    
    if (!strengthElement) return;
    
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

// Form submission handlers
function setupLoginForm() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        // Clear previous errors
        document.querySelectorAll('.error-message').forEach(el => el.textContent = '');

        const formData = { email, password };
        const validation = validateForm(formData);

        if (!validation.isValid) {
            Object.entries(validation.errors).forEach(([field, error]) => {
                const errorElement = document.getElementById(`${field}Error`);
                if (errorElement) errorElement.textContent = error;
            });
            return;
        }

        const button = form.querySelector('button[type="submit"]');
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SECURING...';
        button.disabled = true;

        try {
            await netlifyAuth.login({ email, password });
        } catch (error) {
            // Error handled in auth system
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
        }
    });
}

function setupRegisterForm() {
    const form = document.getElementById('registerForm');
    if (!form) return;

    // Real-time password strength
    const passwordInput = document.getElementById('password');
    const strengthElement = document.getElementById('passwordStrength');
    
    if (passwordInput && strengthElement) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value, strengthElement);
        });
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            firstName: document.getElementById('firstName').value,
            lastName: document.getElementById('lastName').value,
            company: document.getElementById('company').value,
            email: document.getElementById('email').value,
            password: document.getElementById('password').value,
            confirmPassword: document.getElementById('confirmPassword').value,
            role: document.getElementById('role').value
        };

        // Clear previous errors
        document.querySelectorAll('.error-message').forEach(el => el.textContent = '');

        const validation = validateForm(formData);

        if (!formData.role) {
            const roleError = document.getElementById('roleError');
            if (roleError) roleError.textContent = 'Please select your role';
            validation.isValid = false;
        }

        if (formData.password !== formData.confirmPassword) {
            const confirmError = document.getElementById('confirmPasswordError');
            if (confirmError) confirmError.textContent = 'Passwords do not match';
            validation.isValid = false;
        }

        if (!validation.isValid) {
            Object.entries(validation.errors).forEach(([field, error]) => {
                const errorElement = document.getElementById(`${field}Error`);
                if (errorElement) errorElement.textContent = error;
            });
            return;
        }

        const button = form.querySelector('button[type="submit"]');
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> CREATING ACCOUNT...';
        button.disabled = true;

        try {
            await netlifyAuth.register(formData);
            // Redirect to login after successful registration
            setTimeout(() => {
                window.location.href = 'login.html?message=registration_success';
            }, 2000);
        } catch (error) {
            // Error handled in auth system
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
        }
    });
}

// Initialize forms when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    setupLoginForm();
    setupRegisterForm();
    
    // Check for success messages in URL
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('message') === 'registration_success') {
        netlifyAuth.showNotification('Registration successful! Please login to continue.', 'success');
    }
});

// Export for use in other files
window.netlifyAuth = netlifyAuth;
window.validateEmail = validateEmail;
window.validateForm = validateForm;
window.togglePasswordVisibility = togglePasswordVisibility;
window.updatePasswordStrength = updatePasswordStrength;
