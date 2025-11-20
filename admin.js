// admin.js - Creator Control Panel
console.log('👑 Bedusec Creator Panel Initialized');

let currentData = {
    posts: [],
    messages: [],
    partners: [],
    settings: {}
};

// Initialize the control panel
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    setupEventListeners();
    updateDateTime();
    setInterval(updateDateTime, 1000);
});

// Load data from JSON
async function loadData() {
    try {
        const response = await fetch('data/database.json');
        currentData = await response.json();
        updateDashboard();
        loadPosts();
        loadMessages();
        loadPartners();
        loadSettings();
    } catch (error) {
        console.error('Error loading data:', error);
        showNotification('Error loading data', 'error');
    }
}

// Update dashboard stats
function updateDashboard() {
    document.getElementById('totalPosts').textContent = currentData.posts.length;
    document.getElementById('totalMessages').textContent = currentData.messages.length;
    document.getElementById('totalPartners').textContent = currentData.partners.length;
    
    const unreadMessages = currentData.messages.filter(msg => !msg.read).length;
    document.getElementById('unreadCount').textContent = unreadMessages;
    document.getElementById('messagesCount').textContent = unreadMessages;
    document.getElementById('postsCount').textContent = currentData.posts.length;
}

// Tab navigation
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    
    // Activate corresponding nav item
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

// Posts management
function loadPosts() {
    const postsGrid = document.getElementById('postsGrid');
    
    if (currentData.posts.length === 0) {
        postsGrid.innerHTML = '<div class="empty-state">No posts yet. Create your first post!</div>';
        return;
    }
    
    postsGrid.innerHTML = currentData.posts.map(post => `
        <div class="post-card ${post.published ? 'published' : 'draft'}">
            <div class="post-header">
                <h4>${post.title}</h4>
                <span class="post-badge ${post.published ? 'published' : 'draft'}">
                    ${post.published ? 'PUBLISHED' : 'DRAFT'}
                </span>
            </div>
            <div class="post-content">
                <p>${post.content.substring(0, 100)}...</p>
            </div>
            <div class="post-footer">
                <span class="post-date">${post.date}</span>
                <span class="post-category">${post.category}</span>
                <div class="post-actions">
                    <button class="action-btn small" onclick="editPost(${post.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="action-btn small danger" onclick="deletePost(${post.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

// Messages management
function loadMessages() {
    const messagesList = document.getElementById('messagesList');
    
    if (currentData.messages.length === 0) {
        messagesList.innerHTML = '<div class="empty-state">No messages yet.</div>';
        return;
    }
    
    messagesList.innerHTML = currentData.messages.map(message => `
        <div class="message-card ${message.read ? 'read' : 'unread'}">
            <div class="message-header">
                <div class="message-sender">
                    <strong>${message.name}</strong>
                    <span class="message-email">${message.email}</span>
                </div>
                <span class="message-date">${new Date(message.date).toLocaleDateString()}</span>
            </div>
            <div class="message-subject">
                <strong>${message.subject}</strong>
                ${!message.read ? '<span class="unread-badge">NEW</span>' : ''}
            </div>
            <div class="message-content">
                <p>${message.message}</p>
            </div>
            <div class="message-actions">
                <button class="action-btn small" onclick="markAsRead(${message.id})">
                    <i class="fas fa-check"></i> Mark Read
                </button>
                <button class="action-btn small" onclick="replyToMessage(${message.id})">
                    <i class="fas fa-reply"></i> Reply
                </button>
                <button class="action-btn small danger" onclick="deleteMessage(${message.id})">
                    <i class="fas fa-trash"></i> Delete
                </button>
            </div>
        </div>
    `).join('');
}

// Partners management
function loadPartners() {
    const partnersGrid = document.getElementById('partnersGrid');
    
    if (currentData.partners.length === 0) {
        partnersGrid.innerHTML = '<div class="empty-state">No partners yet. Add your first partner!</div>';
        return;
    }
    
    partnersGrid.innerHTML = currentData.partners.map(partner => `
        <div class="partner-card ${partner.featured ? 'featured' : ''}">
            <div class="partner-logo">
                <img src="${partner.logo}" alt="${partner.name}" onerror="this.src='https://via.placeholder.com/150x80/00ff00/000000?text=LOGO'">
            </div>
            <div class="partner-info">
                <h4>${partner.name}</h4>
                <p>${partner.description}</p>
                <a href="${partner.website}" target="_blank" class="partner-website">
                    <i class="fas fa-external-link-alt"></i> Visit Website
                </a>
            </div>
            <div class="partner-actions">
                <button class="action-btn small" onclick="editPartner(${partner.id})">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="action-btn small danger" onclick="deletePartner(${partner.id})">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `).join('');
}

// Settings management
function loadSettings() {
    document.getElementById('siteTitle').value = currentData.settings.siteTitle || '';
    document.getElementById('adminEmail').value = currentData.settings.adminEmail || '';
    document.getElementById('maintenanceMode').checked = currentData.settings.maintenanceMode || false;
    document.getElementById('allowMessages').checked = currentData.settings.allowMessages !== false;
}

// Modal functions
function showPostModal() {
    document.getElementById('postModal').style.display = 'block';
}

function closePostModal() {
    document.getElementById('postModal').style.display = 'none';
    resetPostForm();
}

function showPartnerModal() {
    document.getElementById('partnerModal').style.display = 'block';
}

function closePartnerModal() {
    document.getElementById('partnerModal').style.display = 'none';
    resetPartnerForm();
}

// Save functions (simulated - in real implementation, you'd save to a backend)
function savePost() {
    const title = document.getElementById('postTitle').value;
    const content = document.getElementById('postContent').value;
    const category = document.getElementById('postCategory').value;
    const published = document.getElementById('postPublished').checked;
    
    if (!title || !content) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    const newPost = {
        id: Date.now(),
        title,
        content,
        category,
        published,
        date: new Date().toISOString().split('T')[0],
        author: 'admin'
    };
    
    currentData.posts.unshift(newPost);
    updateDashboard();
    loadPosts();
    closePostModal();
    showNotification('Post created successfully!', 'success');
}

function savePartner() {
    const name = document.getElementById('partnerName').value;
    const website = document.getElementById('partnerWebsite').value;
    const logo = document.getElementById('partnerLogo').value;
    const description = document.getElementById('partnerDescription').value;
    const featured = document.getElementById('partnerFeatured').checked;
    
    if (!name || !website) {
        showNotification('Please fill in required fields', 'error');
        return;
    }
    
    const newPartner = {
        id: Date.now(),
        name,
        website,
        logo: logo || 'https://via.placeholder.com/150x80/00ff00/000000?text=LOGO',
        description,
        featured,
        joined: new Date().toISOString().split('T')[0]
    };
    
    currentData.partners.unshift(newPartner);
    updateDashboard();
    loadPartners();
    closePartnerModal();
    showNotification('Partner added successfully!', 'success');
}

function saveSettings() {
    currentData.settings = {
        siteTitle: document.getElementById('siteTitle').value,
        adminEmail: document.getElementById('adminEmail').value,
        maintenanceMode: document.getElementById('maintenanceMode').checked,
        allowMessages: document.getElementById('allowMessages').checked
    };
    
    showNotification('Settings saved successfully!', 'success');
}

// Utility functions
function resetPostForm() {
    document.getElementById('postTitle').value = '';
    document.getElementById('postContent').value = '';
    document.getElementById('postCategory').value = 'announcement';
    document.getElementById('postPublished').checked = true;
}

function resetPartnerForm() {
    document.getElementById('partnerName').value = '';
    document.getElementById('partnerWebsite').value = '';
    document.getElementById('partnerLogo').value = '';
    document.getElementById('partnerDescription').value = '';
    document.getElementById('partnerFeatured').checked = false;
}

function markAsRead(messageId) {
    const message = currentData.messages.find(msg => msg.id === messageId);
    if (message) {
        message.read = true;
        loadMessages();
        updateDashboard();
        showNotification('Message marked as read', 'success');
    }
}

function deletePost(postId) {
    if (confirm('Are you sure you want to delete this post?')) {
        currentData.posts = currentData.posts.filter(post => post.id !== postId);
        loadPosts();
        updateDashboard();
        showNotification('Post deleted successfully', 'success');
    }
}

function deleteMessage(messageId) {
    if (confirm('Are you sure you want to delete this message?')) {
        currentData.messages = currentData.messages.filter(msg => msg.id !== messageId);
        loadMessages();
        updateDashboard();
        showNotification('Message deleted successfully', 'success');
    }
}

function deletePartner(partnerId) {
    if (confirm('Are you sure you want to delete this partner?')) {
        currentData.partners = currentData.partners.filter(partner => partner.id !== partnerId);
        loadPartners();
        updateDashboard();
        showNotification('Partner deleted successfully', 'success');
    }
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'exclamation-triangle' : 'info'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function updateDateTime() {
    const now = new Date();
    document.getElementById('liveDateTime').textContent = now.toLocaleString();
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = 'index.html';
    }
}

function setupEventListeners() {
    // Tab click events
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const tabName = this.getAttribute('data-tab');
            if (tabName) {
                showTab(tabName);
            }
        });
    });
    
    // Close modals when clicking outside
    window.addEventListener('click', function(e) {
        const postModal = document.getElementById('postModal');
        const partnerModal = document.getElementById('partnerModal');
        
        if (e.target === postModal) {
            closePostModal();
        }
        if (e.target === partnerModal) {
            closePartnerModal();
        }
    });
}

// Placeholder functions for future implementation
function editPost(postId) {
    showNotification('Edit functionality coming soon!', 'info');
}

function editPartner(partnerId) {
    showNotification('Edit functionality coming soon!', 'info');
}

function replyToMessage(messageId) {
    const message = currentData.messages.find(msg => msg.id === messageId);
    if (message) {
        const subject = `Re: ${message.subject}`;
        const body = `Hello ${message.name},\n\nThank you for your message regarding "${message.subject}".\n\nBest regards,\nBedusec Team`;
        
        window.open(`mailto:${message.email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`);
        markAsRead(messageId);
    }
}
