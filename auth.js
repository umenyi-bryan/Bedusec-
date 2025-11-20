// auth.js - Secure Authentication System
class AuthSystem {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.attempts = 0;
        this.maxAttempts = 5;
        this.lockUntil = 0;
    }

    // Initialize authentication system
    init() {
        this.checkExistingSession();
        this.setupAuthInterception();
    }

    // Check if user has existing valid session
    checkExistingSession() {
        const token = localStorage.getItem('bedusec_admin_token');
        const user = localStorage.getItem('bedusec_admin_user');
        const expiry = localStorage.getItem('bedusec_admin_expiry');
        
        if (token && user && expiry && Date.now() < parseInt(expiry)) {
            this.currentUser = JSON.parse(user);
            this.isAuthenticated = true;
            return true;
        } else {
            this.clearSession();
            return false;
        }
    }

    // Setup authentication interception for admin pages
    setupAuthInterception() {
        if (window.location.pathname.includes('admin.html')) {
            if (!this.isAuthenticated) {
                window.location.href = 'login.html';
                return;
            }
        }
    }

    // Login function
    async login(username, password) {
        // Check if account is locked
        if (this.isLocked()) {
            throw new Error('Account temporarily locked. Try again later.');
        }

        // Simulate authentication (in real implementation, this would call a backend)
        const isValid = await this.authenticateUser(username, password);
        
        if (isValid) {
            this.attempts = 0;
            this.lockUntil = 0;
            this.createSession(username);
            return true;
        } else {
            this.attempts++;
            if (this.attempts >= this.maxAttempts) {
                this.lockUntil = Date.now() + (15 * 60 * 1000); // 15 minutes
                throw new Error('Too many failed attempts. Account locked for 15 minutes.');
            }
            throw new Error(`Invalid credentials. ${this.maxAttempts - this.attempts} attempts remaining.`);
        }
    }

    // Simulate user authentication (Replace with real backend in production)
    async authenticateUser(username, password) {
        // For demo purposes - in production, use proper backend authentication
        const validUsers = {
            'admin': this.hashPassword('Bedusec2024!'),
            'creator': this.hashPassword('CyberSecure123!')
        };

        return validUsers[username] === this.hashPassword(password);
    }

    // Simple password hashing (in production, use proper bcrypt)
    hashPassword(password) {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            const char = password.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString();
    }

    // Create user session
    createSession(username) {
        this.currentUser = {
            username: username,
            role: username === 'admin' ? 'superadmin' : 'creator',
            loginTime: new Date().toISOString()
        };
        
        this.isAuthenticated = true;

        // Store session data
        const expiry = Date.now() + (2 * 60 * 60 * 1000); // 2 hours
        localStorage.setItem('bedusec_admin_token', this.generateToken());
        localStorage.setItem('bedusec_admin_user', JSON.stringify(this.currentUser));
        localStorage.setItem('bedusec_admin_expiry', expiry.toString());

        // Set session timeout
        setTimeout(() => {
            this.logout();
            window.location.href = 'login.html?session=expired';
        }, 2 * 60 * 60 * 1000);
    }

    // Generate simple token (in production, use JWT)
    generateToken() {
        return 'bedusec_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // Check if account is locked
    isLocked() {
        return Date.now() < this.lockUntil;
    }

    // Get lock time remaining
    getLockTimeRemaining() {
        if (!this.isLocked()) return 0;
        return Math.ceil((this.lockUntil - Date.now()) / 1000 / 60);
    }

    // Logout function
    logout() {
        this.clearSession();
        window.location.href = 'login.html?logout=success';
    }

    // Clear session data
    clearSession() {
        this.currentUser = null;
        this.isAuthenticated = false;
        localStorage.removeItem('bedusec_admin_token');
        localStorage.removeItem('bedusec_admin_user');
        localStorage.removeItem('bedusec_admin_expiry');
    }

    // Check if user has permission
    hasPermission(permission) {
        if (!this.isAuthenticated) return false;
        
        const permissions = {
            'superadmin': ['all'],
            'creator': ['posts', 'messages', 'partners', 'settings']
        };

        return permissions[this.currentUser.role]?.includes('all') || 
               permissions[this.currentUser.role]?.includes(permission);
    }

    // Get current user info
    getUserInfo() {
        return this.currentUser;
    }
}

// Initialize global auth instance
const bedusecAuth = new AuthSystem();

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = bedusecAuth;
}
