// Bedusec Messaging System
class MessagingSystem {
    constructor() {
        this.messages = JSON.parse(localStorage.getItem('bedusec_messages') || '[]');
        this.init();
    }

    init() {
        this.setupContactForm();
    }

    setupContactForm() {
        document.addEventListener('submit', (e) => {
            if (e.target.matches('#contactForm, .contact-form')) {
                e.preventDefault();
                this.handleContactForm(e.target);
            }
        });
    }

    handleContactForm(form) {
        const formData = new FormData(form);
        const message = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            name: formData.get('name') || 'Anonymous',
            email: formData.get('email') || '',
            subject: formData.get('subject') || 'No Subject',
            message: formData.get('message') || '',
            status: 'new',
            type: 'contact',
            ip: 'local' // In production, get from server
        };

        this.saveMessage(message);
        this.showNotification('Message sent successfully! We will respond within 24 hours.', 'success');
        form.reset();

        // Track the event
        if (window.bedusecAnalytics) {
            window.bedusecAnalytics.trackContactForm();
        }
    }

    saveMessage(message) {
        this.messages.push(message);
        localStorage.setItem('bedusec_messages', JSON.stringify(this.messages));
    }

    getMessages(type = 'all') {
        if (type === 'all') return this.messages;
        return this.messages.filter(msg => msg.type === type);
    }

    getUnreadCount() {
        return this.messages.filter(msg => msg.status === 'new').length;
    }

    markAsRead(messageId) {
        const message = this.messages.find(msg => msg.id === messageId);
        if (message) {
            message.status = 'read';
            localStorage.setItem('bedusec_messages', JSON.stringify(this.messages));
        }
    }

    deleteMessage(messageId) {
        this.messages = this.messages.filter(msg => msg.id !== messageId);
        localStorage.setItem('bedusec_messages', JSON.stringify(this.messages));
    }

    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `cyber-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}

// Initialize messaging system
window.bedusecMessaging = new MessagingSystem();
