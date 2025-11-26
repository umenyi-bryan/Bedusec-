// Bedusec Global Cybersecurity Academy System
class AcademySystem {
    constructor() {
        this.currentUser = null;
        this.userProgress = null;
        this.tutorHistory = [];
        this.init();
    }

    async init() {
        await this.loadUserData();
        this.setupEventListeners();
        this.loadLabs();
        this.updateDashboardStats();
        this.setupTutor();
        this.setupPathCategories();
        this.setupCertificationTabs();
    }

    async loadUserData() {
        // Load user progress from localStorage or create new
        const savedProgress = localStorage.getItem('bedusec_academy_progress');
        if (savedProgress) {
            this.userProgress = JSON.parse(savedProgress);
        } else {
            this.userProgress = {
                enrolledPaths: {},
                completedModules: [],
                completedLabs: [],
                currentLab: null,
                achievements: [],
                totalStudyTime: 0,
                skillLevels: {
                    analysis: 15,
                    penetration: 10,
                    defense: 12,
                    cloud: 8,
                    forensics: 5,
                    governance: 3,
                    mobile: 6,
                    iot: 4,
                    automotive: 2,
                    quantum: 1
                },
                certifications: [],
                mentorSessions: 0
            };
            this.saveProgress();
        }

        // Update UI with user progress
        this.updateProgressUI();
    }

    saveProgress() {
        localStorage.setItem('bedusec_academy_progress', JSON.stringify(this.userProgress));
    }

    setupEventListeners() {
        // Lab category filtering
        document.querySelectorAll('.labs-categories .category').forEach(cat => {
            cat.addEventListener('click', () => {
                document.querySelectorAll('.labs-categories .category').forEach(c => c.classList.remove('active'));
                cat.classList.add('active');
                this.filterLabs(cat.dataset.category);
            });
        });

        // Smooth scrolling for navigation
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    }

    setupPathCategories() {
        document.querySelectorAll('.paths-categories .category').forEach(cat => {
            cat.addEventListener('click', () => {
                document.querySelectorAll('.paths-categories .category').forEach(c => c.classList.remove('active'));
                cat.classList.add('active');
                this.filterPaths(cat.dataset.category);
            });
        });
    }

    setupCertificationTabs() {
        document.querySelectorAll('.cert-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.cert-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                this.filterCertifications(tab.dataset.tab);
            });
        });
    }

    filterPaths(category) {
        const paths = document.querySelectorAll('.path-card');
        paths.forEach(path => {
            if (category === 'all' || path.dataset.category === category) {
                path.style.display = 'block';
                setTimeout(() => {
                    path.style.opacity = '1';
                    path.style.transform = 'translateY(0)';
                }, 50);
            } else {
                path.style.opacity = '0';
                path.style.transform = 'translateY(20px)';
                setTimeout(() => {
                    path.style.display = 'none';
                }, 300);
            }
        });
    }

    filterCertifications(level) {
        const certs = document.querySelectorAll('.certification-card');
        certs.forEach(cert => {
            if (level === 'foundational' || cert.dataset.level === level) {
                cert.style.display = 'block';
                setTimeout(() => {
                    cert.style.opacity = '1';
                    cert.style.transform = 'scale(1)';
                }, 50);
            } else {
                cert.style.opacity = '0';
                cert.style.transform = 'scale(0.8)';
                setTimeout(() => {
                    cert.style.display = 'none';
                }, 300);
            }
        });
    }

    async loadLabs() {
        const labs = [
            {
                id: 'web-sql-injection',
                title: 'Advanced SQL Injection Mastery',
                description: 'Master complex SQL injection techniques including blind, time-based, and out-of-band SQLi.',
                difficulty: 'intermediate',
                category: 'web',
                duration: '3 hours',
                skills: ['web', 'penetration', 'database'],
                completed: this.userProgress.completedLabs.includes('web-sql-injection'),
                rating: 4.8,
                attempts: 1247
            },
            {
                id: 'network-penetration',
                title: 'Network Penetration Testing',
                description: 'Complete network penetration test from reconnaissance to exploitation and persistence.',
                difficulty: 'intermediate',
                category: 'network',
                duration: '4 hours',
                skills: ['network', 'penetration', 'enumeration'],
                completed: this.userProgress.completedLabs.includes('network-penetration'),
                rating: 4.9,
                attempts: 892
            },
            {
                id: 'malware-analysis-advanced',
                title: 'Advanced Malware Analysis',
                description: 'Analyze sophisticated malware samples using static and dynamic analysis techniques.',
                difficulty: 'advanced',
                category: 'forensics',
                duration: '6 hours',
                skills: ['forensics', 'analysis', 'reverse-engineering'],
                completed: this.userProgress.completedLabs.includes('malware-analysis-advanced'),
                rating: 4.7,
                attempts: 567
            },
            {
                id: 'cloud-aws-pentest',
                title: 'AWS Cloud Penetration Testing',
                description: 'Penetration testing for AWS environments including IAM, S3, EC2, and Lambda security.',
                difficulty: 'advanced',
                category: 'cloud',
                duration: '5 hours',
                skills: ['cloud', 'penetration', 'aws'],
                completed: this.userProgress.completedLabs.includes('cloud-aws-pentest'),
                rating: 4.8,
                attempts: 734
            },
            {
                id: 'mobile-app-security',
                title: 'Mobile Application Security',
                description: 'iOS and Android app security testing, reverse engineering, and vulnerability assessment.',
                difficulty: 'intermediate',
                category: 'mobile',
                duration: '4 hours',
                skills: ['mobile', 'reverse-engineering', 'app-security'],
                completed: this.userProgress.completedLabs.includes('mobile-app-security'),
                rating: 4.6,
                attempts: 623
            },
            {
                id: 'ics-scada-security',
                title: 'ICS/SCADA Security Lab',
                description: 'Industrial control systems security assessment and PLC vulnerability testing.',
                difficulty: 'expert',
                category: 'industrial',
                duration: '8 hours',
                skills: ['ics', 'scada', 'critical-infrastructure'],
                completed: this.userProgress.completedLabs.includes('ics-scada-security'),
                rating: 4.9,
                attempts: 289
            },
            {
                id: 'web-application-firewall',
                title: 'WAF Bypass Techniques',
                description: 'Advanced techniques to bypass Web Application Firewalls and intrusion detection systems.',
                difficulty: 'advanced',
                category: 'web',
                duration: '3 hours',
                skills: ['web', 'penetration', 'evasion'],
                completed: this.userProgress.completedLabs.includes('web-application-firewall'),
                rating: 4.7,
                attempts: 845
            },
            {
                id: 'digital-forensics-incident',
                title: 'Digital Forensics & Incident Response',
                description: 'Complete incident response simulation with digital forensics and evidence collection.',
                difficulty: 'intermediate',
                category: 'forensics',
                duration: '5 hours',
                skills: ['forensics', 'incident-response', 'analysis'],
                completed: this.userProgress.completedLabs.includes('digital-forensics-incident'),
                rating: 4.8,
                attempts: 712
            }
        ];

        this.displayLabs(labs);
    }

    displayLabs(labs) {
        const labsGrid = document.getElementById('labsGrid');
        labsGrid.innerHTML = labs.map(lab => `
            <div class="lab-card ${lab.difficulty} ${lab.completed ? 'completed' : ''}" data-category="${lab.category}">
                <div class="lab-header">
                    <div class="lab-difficulty ${lab.difficulty}">${lab.difficulty.toUpperCase()}</div>
                    <div class="lab-category">${lab.category}</div>
                    ${lab.completed ? '<div class="lab-completed"><i class="fas fa-check-circle"></i></div>' : ''}
                </div>
                <h4 class="lab-title">${lab.title}</h4>
                <p class="lab-description">${lab.description}</p>
                <div class="lab-meta">
                    <span class="lab-duration"><i class="fas fa-clock"></i> ${lab.duration}</span>
                    <div class="lab-rating">
                        <i class="fas fa-star"></i> ${lab.rating}
                        <span class="lab-attempts">(${lab.attempts} attempts)</span>
                    </div>
                </div>
                <div class="lab-skills">
                    ${lab.skills.map(skill => `<span class="skill-tag">${skill}</span>`).join('')}
                </div>
                <button class="lab-button ${lab.completed ? 'completed' : ''}" onclick="academySystem.startLab('${lab.id}')">
                    ${lab.completed ? 
                        '<i class="fas fa-redo"></i> REPLAY LAB' : 
                        '<i class="fas fa-play"></i> START LAB'
                    }
                </button>
            </div>
        `).join('');
    }

    filterLabs(category) {
        const labs = document.querySelectorAll('.lab-card');
        labs.forEach(lab => {
            if (category === 'all' || lab.dataset.category === category) {
                lab.style.display = 'block';
                setTimeout(() => {
                    lab.style.opacity = '1';
                    lab.style.transform = 'scale(1)';
                }, 50);
            } else {
                lab.style.opacity = '0';
                lab.style.transform = 'scale(0.8)';
                setTimeout(() => {
                    lab.style.display = 'none';
                }, 300);
            }
        });
    }

    updateProgressUI() {
        // Update path progress
        document.querySelectorAll('.path-card').forEach(card => {
            const path = card.dataset.path;
            const progress = this.userProgress.enrolledPaths[path] || 0;
            const progressFill = card.querySelector('.progress-fill');
            const progressText = card.querySelector('.progress-text');
            
            if (progressFill) progressFill.style.width = `${progress}%`;
            if (progressText) progressText.textContent = `${progress}% Complete`;
        });
    }

    updateDashboardStats() {
        // Simulate live stats updates
        setInterval(() => {
            const stats = {
                totalStudents: Math.floor(47000 + Math.random() * 1000),
                coursesAvailable: 324,
                certifications: 26,
                successRate: 96
            };

            Object.entries(stats).forEach(([id, value]) => {
                const element = document.getElementById(id);
                if (element) {
                    element.textContent = value.toLocaleString();
                }
            });
        }, 5000);
    }

    setupTutor() {
        // Initialize AI tutor
        this.tutorHistory = JSON.parse(localStorage.getItem('bedusec_tutor_history') || '[]');
        this.updateTutorStats();
    }

    async askTutor(question) {
        const chat = document.getElementById('tutorChat');
        const input = document.getElementById('tutorInput');
        
        // Add user question
        this.addMessage(question, 'user');
        
        // Clear input
        input.value = '';
        
        // Show typing indicator
        this.showTypingIndicator();

        // Update mentor sessions count
        this.userProgress.mentorSessions++;
        this.saveProgress();

        try {
            // Simulate AI response (in real implementation, this would call an AI API)
            const response = await this.generateTutorResponse(question);
            
            // Remove typing indicator and add response
            this.removeTypingIndicator();
            this.addMessage(response, 'ai');

            // Update stats
            this.updateTutorStats();

        } catch (error) {
            this.removeTypingIndicator();
            this.addMessage('I apologize, but I encountered an error. Please try again.', 'ai');
        }
    }

    async generateTutorResponse(question) {
        // Simulate API call delay
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));

        // Enhanced response logic with more comprehensive answers
        const responses = {
            'sql injection': `# Advanced SQL Injection Techniques

SQL Injection is one of the most critical web application vulnerabilities. Here's a comprehensive overview:

## Types of SQL Injection:
1. **Classic SQLi** - Direct injection through user input
2. **Blind SQLi** - No direct output, infer from behavior
3. **Time-based Blind SQLi** - Use timing delays to extract data
4. **Out-of-band SQLi** - Use alternative channels (DNS, HTTP)

## Advanced Example (Time-based Blind SQLi):
\`\`\`sql
' AND (SELECT sleep(5) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--
\`\`\`

## Prevention Methods:
• Parameterized queries (prepared statements)
• Input validation and sanitization
• Least privilege database accounts
• Web Application Firewalls (WAF)
• Regular security testing

## Tools for Testing:
• SQLmap (automated)
• Burp Suite (manual)
• Custom scripts

Would you like me to explain any specific technique in more detail?`,

            'soc setup': `# Building a Security Operations Center (SOC)

A modern SOC requires careful planning and implementation:

## Core Components:
1. **SIEM (Security Information and Event Management)**
   - Splunk, Elastic Stack, IBM QRadar
   - Log aggregation and correlation
   - Real-time alerting

2. **Monitoring Tools**
   - EDR (Endpoint Detection and Response)
   - NDR (Network Detection and Response)
   - Cloud security monitoring

3. **Threat Intelligence**
   - Open source intelligence (OSINT)
   - Commercial threat feeds
   - Internal threat data

## SOC Team Structure:
• Tier 1 - Monitoring and triage
• Tier 2 - Incident analysis
• Tier 3 - Threat hunting and advanced analysis
• SOC Manager - Oversight and reporting

## Key Metrics:
• Mean Time to Detect (MTTD)
• Mean Time to Respond (MTTR)
• False positive rate
• Incident closure rate

## Implementation Steps:
1. Define use cases and detection rules
2. Establish log collection pipeline
3. Configure monitoring and alerting
4. Develop incident response procedures
5. Continuous improvement and tuning`,

            'code review': `# Cybersecurity Code Review Checklist

I'd be happy to review your code! Please paste the code you want me to analyze.

## Common Security Issues I Check For:

### 1. Input Validation
• SQL Injection vulnerabilities
• Cross-site Scripting (XSS)
• Command Injection
• Path Traversal

### 2. Authentication & Authorization
• Weak password policies
• Session management issues
• Privilege escalation vulnerabilities
• Broken access control

### 3. Data Protection
• Sensitive data exposure
• Insecure cryptographic storage
• Lack of encryption in transit
• Improper error handling

### 4. Configuration Security
• Hardcoded secrets
• Insecure default configurations
• Missing security headers
• Verbose error messages

### Example Vulnerable Code:
\`\`\`python
# Vulnerable: SQL Injection
query = "SELECT * FROM users WHERE username = '" + username + "'"

# Secure: Parameterized query
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
\`\`\`

Please share your code, and I'll provide specific security recommendations!`,

            'zero trust': `# Zero Trust Architecture Implementation

Zero Trust is a security model based on "never trust, always verify."

## Core Principles:
1. **Verify Explicitly** - Authenticate and authorize based on all available data points
2. **Use Least Privilege** - Limit user access with Just-In-Time and Just-Enough-Access
3. **Assume Breach** - Segment access and minimize blast radius

## Implementation Components:

### Identity and Access Management
• Multi-factor authentication (MFA) everywhere
• Conditional access policies
• Identity governance

### Device Security
• Device health compliance
• Endpoint detection and response
• Mobile device management

### Network Security
• Micro-segmentation
• Software-defined perimeters
• Encrypted communications

### Application Security
• Application segmentation
• Secure access service edge (SASE)
• API security

### Data Security
• Data classification
• Encryption at rest and in transit
• Data loss prevention

## Steps to Implement:
1. Identify sensitive data and services
2. Map transaction flows
3. Architect zero trust network
4. Create zero trust policies
5. Monitor and maintain

Would you like me to dive deeper into any specific aspect?`,

            'default': `# Comprehensive Cybersecurity Guidance

I'd be happy to help you with that! As your AI Cyber Mentor, I can assist with:

## Technical Domains:
• **Offensive Security** - Penetration testing, ethical hacking, red teaming
• **Defensive Security** - SOC operations, incident response, threat hunting
• **Digital Forensics** - Evidence collection, malware analysis, incident investigation
• **Cloud Security** - AWS, Azure, GCP security architecture and testing
• **Application Security** - Secure coding, code review, vulnerability assessment

## Emerging Technologies:
• **IoT Security** - Connected devices, embedded systems
• **Automotive Security** - Vehicle networks, CAN bus security
• **Quantum Security** - Post-quantum cryptography
• **AI Security** - Adversarial machine learning, model security

## Career & Certification Guidance:
• Career path planning
• Certification preparation (CEH, CISSP, OSCP, etc.)
• Interview preparation
• Skill development roadmaps

Please provide more details about what specific area you'd like to explore, and I'll give you comprehensive, actionable guidance!`
        };

        const lowerQuestion = question.toLowerCase();
        
        if (lowerQuestion.includes('sql injection')) {
            return responses['sql injection'];
        } else if (lowerQuestion.includes('soc') || lowerQuestion.includes('security operations')) {
            return responses['soc setup'];
        } else if (lowerQuestion.includes('code review') || lowerQuestion.includes('review this')) {
            return responses['code review'];
        } else if (lowerQuestion.includes('zero trust')) {
            return responses['zero trust'];
        } else {
            return responses['default'];
        }
    }

    addMessage(content, type) {
        const chat = document.getElementById('tutorChat');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}-message`;
        
        const sender = type === 'user' ? 'You' : 'CyberAI Mentor';
        messageDiv.innerHTML = `
            <div class="message-content">
                <strong>${sender}:</strong> ${this.formatMessageContent(content)}
            </div>
        `;
        
        chat.appendChild(messageDiv);
        chat.scrollTop = chat.scrollHeight;

        // Save to history
        this.tutorHistory.push({ type, content, timestamp: new Date().toISOString() });
        localStorage.setItem('bedusec_tutor_history', JSON.stringify(this.tutorHistory));
    }

    formatMessageContent(content) {
        // Convert markdown-like formatting to HTML
        return content
            .replace(/^# (.*$)/gim, '<h4>$1</h4>')
            .replace(/^## (.*$)/gim, '<h5>$1</h5>')
            .replace(/^### (.*$)/gim, '<h6>$1</h6>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
            .replace(/\n/g, '<br>');
    }

    showTypingIndicator() {
        const chat = document.getElementById('tutorChat');
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message ai-message typing-indicator';
        typingDiv.id = 'typingIndicator';
        typingDiv.innerHTML = `
            <div class="message-content">
                <strong>CyberAI Mentor:</strong> <span class="typing-dots"></span>
            </div>
        `;
        
        chat.appendChild(typingDiv);
        chat.scrollTop = chat.scrollHeight;
    }

    removeTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }

    updateTutorStats() {
        const questionsAnswered = this.tutorHistory.filter(msg => msg.type === 'user').length;
        document.getElementById('questionsAnswered').textContent = (287451 + questionsAnswered).toLocaleString();
        
        // Update other stats
        document.getElementById('conceptsExplained').textContent = (1247 + Math.floor(questionsAnswered * 0.1)).toLocaleString();
        document.getElementById('codeReviews').textContent = (42836 + Math.floor(questionsAnswered * 0.3)).toLocaleString();
    }

    enrollPath(pathId) {
        if (!this.isUserAuthenticated()) {
            this.showNotification('Please login to enroll in learning paths', 'warning');
            return;
        }

        if (!this.userProgress.enrolledPaths[pathId]) {
            this.userProgress.enrolledPaths[pathId] = 0;
            this.saveProgress();
            this.updateProgressUI();
            
            this.showNotification(`Enrolled in ${this.getPathName(pathId)} path!`, 'success');
        } else {
            this.showNotification('You are already enrolled in this path', 'info');
        }
    }

    getPathName(pathId) {
        const paths = {
            'ethical-hacker': 'Certified Ethical Hacker',
            'red-team': 'Red Team Operator',
            'soc-analyst': 'SOC Analyst',
            'threat-hunter': 'Threat Hunter',
            'ciso': 'CISO Executive',
            'quantum-security': 'Quantum Cryptography'
        };
        return paths[pathId] || pathId;
    }

    startLab(labId) {
        if (!this.isUserAuthenticated()) {
            this.showNotification('Please login to access labs', 'warning');
            return;
        }

        this.showNotification(`Launching lab: ${this.getLabName(labId)}`, 'info');
        // In a real implementation, this would redirect to the lab environment
        
        // Simulate lab completion after delay
        setTimeout(() => {
            if (!this.userProgress.completedLabs.includes(labId)) {
                this.userProgress.completedLabs.push(labId);
                this.saveProgress();
                this.loadLabs(); // Refresh labs display
                this.showNotification(`Lab completed: ${this.getLabName(labId)}`, 'success');
            }
        }, 5000);
    }

    getLabName(labId) {
        const labs = {
            'web-sql-injection': 'Advanced SQL Injection Mastery',
            'network-penetration': 'Network Penetration Testing',
            'malware-analysis-advanced': 'Advanced Malware Analysis',
            'cloud-aws-pentest': 'AWS Cloud Penetration Testing',
            'mobile-app-security': 'Mobile Application Security',
            'ics-scada-security': 'ICS/SCADA Security Lab',
            'web-application-firewall': 'WAF Bypass Techniques',
            'digital-forensics-incident': 'Digital Forensics & Incident Response'
        };
        return labs[labId] || labId;
    }

    viewCertification(certId) {
        this.showNotification(`Viewing certification details: ${this.getCertName(certId)}`, 'info');
        // In a real implementation, this would show certification details modal
    }

    getCertName(certId) {
        const certs = {
            'bcsa': 'Bedusec Certified Security Analyst',
            'bnd': 'Bedusec Network Defender',
            'bceh': 'Bedusec Certified Ethical Hacker',
            'bcse': 'Bedusec Cloud Security Expert',
            'brto': 'Bedusec Red Team Operator',
            'bciso': 'Bedusec Chief Information Security Officer'
        };
        return certs[certId] || certId;
    }

    isUserAuthenticated() {
        // Check if user is logged in (simplified)
        return localStorage.getItem('bedusec_user') !== null;
    }

    showNotification(message, type = 'info') {
        // Create and show a notification
        const notification = document.createElement('div');
        notification.className = `cyber-notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    showAllPaths() {
        this.showNotification('Displaying all 47 career paths...', 'info');
        // Implementation to show modal with all paths
    }
}

// Initialize the academy system when page loads
document.addEventListener('DOMContentLoaded', function() {
    window.academySystem = new AcademySystem();
});
