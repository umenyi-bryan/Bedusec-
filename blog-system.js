// Bedusec Blog System
class BlogSystem {
    constructor() {
        this.posts = JSON.parse(localStorage.getItem('bedusec_posts') || '[]');
        this.init();
    }

    init() {
        this.loadSamplePosts();
    }

    loadSamplePosts() {
        if (this.posts.length === 0) {
            const samplePosts = [
                {
                    id: this.generateId(),
                    title: "Understanding SQL Injection Attacks",
                    content: "SQL Injection remains one of the most critical web application vulnerabilities. In this comprehensive guide, we explore various SQLi techniques and prevention methods...",
                    excerpt: "Learn about SQL Injection attacks and how to protect your applications from this critical vulnerability.",
                    author: "Alex Chen",
                    category: "Web Security",
                    tags: ["sql-injection", "web-security", "penetration-testing"],
                    status: "published",
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                    views: 0,
                    featured: true
                },
                {
                    id: this.generateId(),
                    title: "Advanced Nmap Scanning Techniques",
                    content: "Nmap is the go-to tool for network discovery and security auditing. This advanced guide covers stealth scanning, version detection, and NSE scripting...",
                    excerpt: "Master advanced Nmap scanning techniques for comprehensive network security assessment.",
                    author: "Sarah Martinez",
                    category: "Network Security",
                    tags: ["nmap", "network-scanning", "penetration-testing"],
                    status: "published",
                    createdAt: new Date(Date.now() - 86400000).toISOString(),
                    updatedAt: new Date(Date.now() - 86400000).toISOString(),
                    views: 0,
                    featured: false
                }
            ];
            this.posts = samplePosts;
            this.savePosts();
        }
    }

    createPost(postData) {
        const post = {
            id: this.generateId(),
            title: postData.title,
            content: postData.content,
            excerpt: postData.excerpt || postData.content.substring(0, 150) + '...',
            author: postData.author || 'Admin',
            category: postData.category || 'General',
            tags: postData.tags || [],
            status: postData.status || 'draft',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            views: 0,
            featured: postData.featured || false
        };

        this.posts.unshift(post);
        this.savePosts();
        return post;
    }

    updatePost(postId, updates) {
        const postIndex = this.posts.findIndex(post => post.id === postId);
        if (postIndex !== -1) {
            this.posts[postIndex] = {
                ...this.posts[postIndex],
                ...updates,
                updatedAt: new Date().toISOString()
            };
            this.savePosts();
            return this.posts[postIndex];
        }
        return null;
    }

    deletePost(postId) {
        this.posts = this.posts.filter(post => post.id !== postId);
        this.savePosts();
    }

    getPosts(status = 'published') {
        if (status === 'all') return this.posts;
        return this.posts.filter(post => post.status === status);
    }

    getPostById(postId) {
        const post = this.posts.find(post => post.id === postId);
        if (post) {
            post.views++;
            this.savePosts();
        }
        return post;
    }

    getFeaturedPosts() {
        return this.posts.filter(post => post.featured && post.status === 'published');
    }

    getPostsByCategory(category) {
        return this.posts.filter(post => post.category === category && post.status === 'published');
    }

    savePosts() {
        localStorage.setItem('bedusec_posts', JSON.stringify(this.posts));
    }

    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
}

// Initialize blog system
window.bedusecBlog = new BlogSystem();
