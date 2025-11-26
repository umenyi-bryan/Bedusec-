// Bedusec Analytics Tracker
class AnalyticsTracker {
    constructor() {
        this.visits = JSON.parse(localStorage.getItem('bedusec_visits') || '[]');
        this.pageViews = JSON.parse(localStorage.getItem('bedusec_pageviews') || '[]');
        this.init();
    }

    init() {
        this.trackVisit();
        this.trackPageView();
        this.setupEventListeners();
    }

    trackVisit() {
        const visit = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            referrer: document.referrer,
            screen: `${screen.width}x${screen.height}`,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };

        this.visits.push(visit);
        localStorage.setItem('bedusec_visits', JSON.stringify(this.visits));
    }

    trackPageView() {
        const pageView = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            page: window.location.pathname,
            title: document.title,
            duration: 0 // Will be updated when user leaves
        };

        this.pageViews.push(pageView);
        localStorage.setItem('bedusec_pageviews', JSON.stringify(this.pageViews));

        // Track time on page
        window.addEventListener('beforeunload', () => {
            const duration = Date.now() - new Date(pageView.timestamp).getTime();
            pageView.duration = duration;
            localStorage.setItem('bedusec_pageviews', JSON.stringify(this.pageViews));
        });
    }

    trackEvent(category, action, label = '') {
        const event = {
            id: this.generateId(),
            timestamp: new Date().toISOString(),
            category,
            action,
            label,
            page: window.location.pathname
        };

        const events = JSON.parse(localStorage.getItem('bedusec_events') || '[]');
        events.push(event);
        localStorage.setItem('bedusec_events', JSON.stringify(events));
    }

    trackContactForm() {
        this.trackEvent('forms', 'contact_submitted');
    }

    trackToolUsage(toolName) {
        this.trackEvent('tools', 'tool_used', toolName);
    }

    trackAcademyAccess() {
        this.trackEvent('academy', 'academy_accessed');
    }

    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    setupEventListeners() {
        // Track form submissions
        document.addEventListener('submit', (e) => {
            if (e.target.matches('form')) {
                this.trackEvent('forms', 'form_submitted', e.target.id || 'unknown_form');
            }
        });

        // Track external links
        document.addEventListener('click', (e) => {
            if (e.target.matches('a[href^="http"]') && !e.target.href.includes(window.location.hostname)) {
                this.trackEvent('engagement', 'external_link_clicked', e.target.href);
            }
        });

        // Track tool usage
        document.addEventListener('click', (e) => {
            if (e.target.matches('.tool-card, .tool-button, .access-card')) {
                const toolName = e.target.textContent.trim() || e.target.querySelector('span')?.textContent || 'unknown_tool';
                this.trackToolUsage(toolName);
            }
        });
    }

    // Analytics data getters
    getVisits() {
        return this.visits;
    }

    getPageViews() {
        return this.pageViews;
    }

    getEvents() {
        return JSON.parse(localStorage.getItem('bedusec_events') || '[]');
    }

    getUniqueVisitors() {
        // Simple unique count based on day (in production, use better methods)
        const uniqueDays = new Set(this.visits.map(v => v.timestamp.split('T')[0]));
        return uniqueDays.size;
    }

    getPopularPages() {
        const pages = {};
        this.pageViews.forEach(pv => {
            pages[pv.page] = (pages[pv.page] || 0) + 1;
        });
        return Object.entries(pages).sort((a, b) => b[1] - a[1]);
    }

    getToolUsage() {
        const events = this.getEvents();
        const toolEvents = events.filter(e => e.category === 'tools');
        const usage = {};
        toolEvents.forEach(event => {
            usage[event.label] = (usage[event.label] || 0) + 1;
        });
        return Object.entries(usage).sort((a, b) => b[1] - a[1]);
    }
}

// Initialize analytics
window.bedusecAnalytics = new AnalyticsTracker();
