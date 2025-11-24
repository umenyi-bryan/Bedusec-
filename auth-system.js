// auth-system.js - Real User Authentication
class UserAuth {
    constructor() {
        this.currentUser = null;
        this.isAuthenticated = false;
        this.users = this.loadUsers();
    }

    loadUsers() {
        return JSON.parse(localStorage.getItem('bedusec_users')) || [];
    }

    saveUsers() {
        localStorage.setItem('bedusec_users', JSON.stringify(this.users));
    }

    // Register new user
    async register(userData) {
        const { username, email, password, plan = 'free' } = userData;
        
        // Validation
        if (!username || !email || !password) {
            throw new Error('All fields are required');
        }

        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }

        if (this.users.find(u => u.email === email)) {
            throw new Error('Email already registered');
        }

        if (this.users.find(u => u.username === username)) {
            throw new Error('Username already taken');
        }

        // Create user
        const user = {
            id: this.generateId(),
            username,
            email,
            password: this.hashPassword(password),
            plan,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true,
            profile: {
                level: 'beginner',
                experience: 0,
                badges: ['new_recruit']
            }
        };

        this.users.push(user);
        this.saveUsers();

        // Auto-login after registration
        return this.login(email, password);
    }

    // Login user
    async login(email, password) {
        const user = this.users.find(u => u.email === email && u.isActive);
        
        if (!user) {
            throw new Error('Invalid credentials');
        }

        if (user.password !== this.hashPassword(password)) {
            throw new Error('Invalid credentials');
        }

        // Update last login
        user.lastLogin = new Date().toISOString();
        this.saveUsers();

        // Create session
        this.currentUser = { ...user };
        delete this.currentUser.password; // Don't store password in session
        this.isAuthenticated = true;

        this.createSession(user);
        return user;
    }

    // Create session
    createSession(user) {
        const session = {
            userId: user.id,
            token: this.generateToken(),
            expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
        };

        localStorage.setItem('bedusec_session', JSON.stringify(session));
        localStorage.setItem('bedusec_user', JSON.stringify(user));
    }

    // Check existing session
    checkSession() {
        const session = JSON.parse(localStorage.getItem('bedusec_session'));
        const user = JSON.parse(localStorage.getItem('bedusec_user'));

        if (session && user && Date.now() < session.expiresAt) {
            this.currentUser = user;
            this.isAuthenticated = true;
            return true;
        }

        this.logout();
        return false;
    }

    // Logout
    logout() {
        this.currentUser = null;
        this.isAuthenticated = false;
        localStorage.removeItem('bedusec_session');
        localStorage.removeItem('bedusec_user');
    }

    // Update user profile
    updateProfile(updates) {
        if (!this.isAuthenticated) return false;

        const userIndex = this.users.findIndex(u => u.id === this.currentUser.id);
        if (userIndex === -1) return false;

        this.users[userIndex] = { ...this.users[userIndex], ...updates };
        this.currentUser = { ...this.currentUser, ...updates };
        
        this.saveUsers();
        localStorage.setItem('bedusec_user', JSON.stringify(this.currentUser));
        
        return true;
    }

    // Utility functions
    generateId() {
        return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    generateToken() {
        return 'token_' + Date.now() + '_' + Math.random().toString(36).substr(2, 16);
    }

    hashPassword(password) {
        // Simple hash for demo - in production use bcrypt
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            const char = password.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString();
    }

    // Get user by ID
    getUserById(id) {
        return this.users.find(u => u.id === id);
    }

    // Get all users (admin only)
    getAllUsers() {
        return this.users.map(u => {
            const { password, ...userWithoutPassword } = u;
            return userWithoutPassword;
        });
    }
}

// Initialize global auth instance
const userAuth = new UserAuth();

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = userAuth;
}
