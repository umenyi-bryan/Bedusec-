// admin-secure.js - Secure Admin Panel
console.log('🔐 Secure Admin Panel Initializing...');

// Wait for auth system to load
document.addEventListener('DOMContentLoaded', async function() {
    // Check authentication
    if (!bedusecAuth.isAuthenticated) {
        console.warn('Unauthorized access attempt detected');
        window.location.href = 'login.html?error=unauthorized';
        return;
    }

    // Initialize the admin panel
    await initializeSecureAdmin();
});

async function initializeSecureAdmin() {
    const user = bedusecAuth.getUserInfo();
    console.log(`👑 Welcome, ${user.username} (${user.role})`);
    
    // Update UI with user info
    updateUserInterface(user);
    
    // Load admin functionality
    await loadData();
    setupEventListeners();
    updateDateTime();
    setInterval(updateDateTime, 1000);

    // Add logout functionality
    setupLogoutHandler();
}

function updateUserInterface(user) {
    // Update sidebar header
    const adminAvatar = document.querySelector('.admin-avatar');
    const adminName = document.querySelector('.sidebar-header h3');
    
    if (adminAvatar && adminName) {
        adminAvatar.innerHTML = `<i class="fas fa-${user.role === 'superadmin' ? 'crown' : 'user-shield'}"></i>`;
        adminName.textContent = user.username;
        
        // Add role badge
        const roleBadge = document.createElement('span');
        roleBadge.className = 'role-badge';
        roleBadge.textContent = user.role.toUpperCase();
        roleBadge.style.cssText = `
            display: block;
            font-size: 0.8rem;
            color: #ff0080;
            margin-top: 0.25rem;
        `;
        adminName.parentNode.appendChild(roleBadge);
    }

    // Update header
    const headerTitle = document.querySelector('.dashboard-header h1');
    if (headerTitle) {
        headerTitle.textContent = `CONTROL PANEL - ${user.role.toUpperCase()}`;
    }
}

function setupLogoutHandler() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.onclick = function() {
            if (confirm('Are you sure you want to logout?')) {
                bedusecAuth.logout();
            }
        };
    }
}

// Enhanced security functions
function checkPermissions() {
    const user = bedusecAuth.getUserInfo();
    
    // Hide superadmin-only features for non-superadmins
    if (user.role !== 'superadmin') {
        const superadminFeatures = document.querySelectorAll('.superadmin-only');
        superadminFeatures.forEach(feature => {
            feature.style.display = 'none';
        });
    }
}

// Activity logging
function logAdminActivity(action, details = {}) {
    const user = bedusecAuth.getUserInfo();
    const activity = {
        user: user.username,
        role: user.role,
        action: action,
        details: details,
        timestamp: new Date().toISOString(),
        ip: 'logged' // In real implementation, get client IP
    };
    
    console.log('🔐 Admin Activity:', activity);
    // In production, send this to your logging service
}

// Override sensitive functions to include logging
const originalSavePost = window.savePost;
window.savePost = function() {
    logAdminActivity('create_post', {
        title: document.getElementById('postTitle')?.value
    });
    return originalSavePost?.apply(this, arguments);
};

const originalDeletePost = window.deletePost;
window.deletePost = function(postId) {
    logAdminActivity('delete_post', { postId });
    return originalDeletePost?.apply(this, arguments);
};

// Session timeout warning
function setupSessionWarning() {
    // Warn user 5 minutes before session expiry
    setTimeout(() => {
        if (bedusecAuth.isAuthenticated) {
            const warning = confirm('Your session will expire in 5 minutes. Would you like to extend it?');
            if (warning) {
                // Refresh session (in real implementation, this would call backend)
                console.log('Session extended by user request');
            }
        }
    }, 90 * 60 * 1000); // 90 minutes
}

// Export for use in HTML
window.bedusecAuth = bedusecAuth;
