// tools.js - OSINT & Security Tools
console.log('🔍 Bedusec OSINT Tools Initialized');

async function runIPLookup() {
    const ip = document.getElementById('ipInput').value;
    const resultsDiv = document.getElementById('ipResults');
    
    if (!ip) {
        resultsDiv.innerHTML = '<div class="error">Enter an IP address</div>';
        return;
    }

    resultsDiv.innerHTML = '<div class="loading">Tracing IP location...</div>';
    
    try {
        // Using ipapi.co free tier
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        const data = await response.json();
        
        if (data.error) {
            resultsDiv.innerHTML = `<div class="error">Error: ${data.reason}</div>`;
            return;
        }
        
        resultsDiv.innerHTML = `
            <div class="success">
                <h4>📍 IP Location Data</h4>
                <p><strong>IP:</strong> ${data.ip}</p>
                <p><strong>Country:</strong> ${data.country_name} (${data.country_code})</p>
                <p><strong>Region:</strong> ${data.region}</p>
                <p><strong>City:</strong> ${data.city}</p>
                <p><strong>ISP:</strong> ${data.org}</p>
                <p><strong>Timezone:</strong> ${data.timezone}</p>
            </div>
        `;
    } catch (error) {
        resultsDiv.innerHTML = '<div class="error">Failed to fetch IP data</div>';
    }
}

function analyzePassword() {
    const password = document.getElementById('passwordInput').value;
    const resultsDiv = document.getElementById('passwordResults');
    
    if (!password) {
        resultsDiv.innerHTML = '<div class="error">Enter a password to analyze</div>';
        return;
    }

    const strength = {
        score: 0,
        feedback: []
    };
    
    // Length check
    if (password.length >= 12) strength.score += 2;
    else if (password.length >= 8) strength.score += 1;
    else strength.feedback.push('❌ Too short (min 8 characters, 12 recommended)');
    
    // Complexity checks
    if (/[A-Z]/.test(password)) strength.score += 1;
    else strength.feedback.push('❌ Add uppercase letters');
    
    if (/[a-z]/.test(password)) strength.score += 1;
    else strength.feedback.push('❌ Add lowercase letters');
    
    if (/[0-9]/.test(password)) strength.score += 1;
    else strength.feedback.push('❌ Add numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) strength.score += 1;
    else strength.feedback.push('❌ Add special characters');
    
    // Common password check
    const commonPasswords = ['password', '123456', 'qwerty', 'letmein'];
    if (commonPasswords.includes(password.toLowerCase())) {
        strength.score = 0;
        strength.feedback.push('❌ CRITICAL: This is a very common password');
    }
    
    // Determine strength level
    let strengthLevel = 'Very Weak';
    let strengthClass = 'critical';
    
    if (strength.score >= 5) {
        strengthLevel = 'Very Strong';
        strengthClass = 'safe';
    } else if (strength.score >= 4) {
        strengthLevel = 'Strong';
        strengthClass = 'safe';
    } else if (strength.score >= 3) {
        strengthLevel = 'Moderate';
        strengthClass = 'warning';
    } else if (strength.score >= 2) {
        strengthLevel = 'Weak';
        strengthClass = 'warning';
    }
    
    resultsDiv.innerHTML = `
        <div class="${strengthClass}">
            <h4>Password Strength: ${strengthLevel}</h4>
            <p><strong>Score:</strong> ${strength.score}/6</p>
            <div class="feedback">
                ${strength.feedback.map(item => `<p>${item}</p>`).join('')}
            </div>
        </div>
    `;
}

async function simulatePortScan() {
    const target = document.getElementById('scanTarget').value;
    const resultsDiv = document.getElementById('scanResults');
    
    if (!target) {
        resultsDiv.innerHTML = '<div class="error">Enter a target domain or IP</div>';
        return;
    }

    resultsDiv.innerHTML = '<div class="loading">Scanning common ports...</div>';
    
    // Simulate scanning delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const commonPorts = {
        21: { service: 'FTP', description: 'File Transfer Protocol' },
        22: { service: 'SSH', description: 'Secure Shell' },
        23: { service: 'Telnet', description: 'Remote Login' },
        25: { service: 'SMTP', description: 'Email Transfer' },
        53: { service: 'DNS', description: 'Domain Name System' },
        80: { service: 'HTTP', description: 'Web Traffic' },
        110: { service: 'POP3', description: 'Email Retrieval' },
        143: { service: 'IMAP', description: 'Email Management' },
        443: { service: 'HTTPS', description: 'Secure Web' },
        993: { service: 'IMAPS', description: 'Secure IMAP' },
        995: { service: 'POP3S', description: 'Secure POP3' },
        3389: { service: 'RDP', description: 'Remote Desktop' }
    };
    
    const openPorts = [];
    
    // Simulate random port states (for demo purposes)
    for (const [port, info] of Object.entries(commonPorts)) {
        if (Math.random() > 0.7) { // 30% chance port is "open"
            openPorts.push({
                port: port,
                service: info.service,
                description: info.description,
                risk: getRiskLevel(port)
            });
        }
    }
    
    if (openPorts.length === 0) {
        resultsDiv.innerHTML = '<div class="safe">No common ports found open</div>';
        return;
    }
    
    const resultsHTML = openPorts.map(port => `
        <div class="port-result ${port.risk}">
            <strong>Port ${port.port}</strong> - ${port.service}
            <br><small>${port.description}</small>
            <br><span class="risk-tag">${port.risk.toUpperCase()} RISK</span>
        </div>
    `).join('');
    
    resultsDiv.innerHTML = `
        <div class="scan-results">
            <h4>Open Ports Found on ${target}</h4>
            ${resultsHTML}
            <p class="disclaimer">This is a simulation for educational purposes</p>
        </div>
    `;
}

function getRiskLevel(port) {
    const portNum = parseInt(port);
    if ([21, 23, 25, 110, 143].includes(portNum)) return 'critical';
    if ([22, 53, 80, 443, 993, 995].includes(portNum)) return 'warning';
    return 'safe';
}

async function checkHeaders() {
    const url = document.getElementById('headerUrl').value;
    const resultsDiv = document.getElementById('headerResults');
    
    if (!url) {
        resultsDiv.innerHTML = '<div class="error">Enter a URL to analyze</div>';
        return;
    }

    resultsDiv.innerHTML = '<div class="loading">Analyzing HTTP headers...</div>';
    
    try {
        const response = await fetch(url);
        const headers = {};
        
        // Get all headers
        response.headers.forEach((value, key) => {
            headers[key] = value;
        });
        
        // Analyze security headers
        const securityAnalysis = analyzeSecurityHeaders(headers);
        
        const headersHTML = Object.entries(headers).map(([key, value]) => `
            <div class="header-item">
                <strong>${key}:</strong> ${value}
            </div>
        `).join('');
        
        const securityHTML = Object.entries(securityAnalysis).map(([header, status]) => `
            <div class="security-item ${status.status}">
                <strong>${header}:</strong> ${status.message}
            </div>
        `).join('');
        
        resultsDiv.innerHTML = `
            <div class="header-results">
                <h4>HTTP Headers for ${url}</h4>
                <div class="headers-list">
                    ${headersHTML}
                </div>
                <h4>Security Analysis</h4>
                <div class="security-analysis">
                    ${securityHTML}
                </div>
            </div>
        `;
        
    } catch (error) {
        resultsDiv.innerHTML = '<div class="error">Failed to fetch headers. CORS may be blocking the request.</div>';
    }
}

function analyzeSecurityHeaders(headers) {
    const analysis = {};
    
    // Check for common security headers
    const securityHeaders = {
        'Strict-Transport-Security': {
            check: (value) => value && value.includes('max-age'),
            message: 'Forces HTTPS connections'
        },
        'Content-Security-Policy': {
            check: (value) => value && value.length > 0,
            message: 'Prevents XSS attacks'
        },
        'X-Frame-Options': {
            check: (value) => value && ['DENY', 'SAMEORIGIN'].includes(value),
            message: 'Prevents clickjacking'
        },
        'X-Content-Type-Options': {
            check: (value) => value && value === 'nosniff',
            message: 'Prevents MIME sniffing'
        },
        'Referrer-Policy': {
            check: (value) => value && value.length > 0,
            message: 'Controls referrer information'
        }
    };
    
    for (const [header, config] of Object.entries(securityHeaders)) {
        const value = headers[header] || headers[header.toLowerCase()];
        const isPresent = config.check(value);
        
        analysis[header] = {
            status: isPresent ? 'safe' : 'warning',
            message: isPresent ? '✅ Present' : '❌ Missing - ' + config.message
        };
    }
    
    return analysis;
}

// Add CSS for tool results
const toolStyles = document.createElement('style');
toolStyles.textContent = `
    .tools-hero {
        padding: 120px 0 60px;
        text-align: center;
    }
    
    .tools-grid {
        padding: 40px 0;
    }
    
    .tool-card {
        background: rgba(0, 30, 0, 0.8);
        border: 1px solid #00ff00;
        border-radius: 8px;
        padding: 2rem;
        margin-bottom: 2rem;
    }
    
    .tool-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .tool-header i {
        font-size: 2rem;
        color: #00ff00;
    }
    
    .tool-body {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }
    
    .tool-results {
        min-height: 50px;
        margin-top: 1rem;
    }
    
    .loading {
        color: #0088ff;
        font-style: italic;
    }
    
    .error {
        color: #ff4444;
        border: 1px solid #ff4444;
        padding: 1rem;
        border-radius: 4px;
    }
    
    .success, .safe {
        color: #00ff00;
        border: 1px solid #00ff00;
        padding: 1rem;
        border-radius: 4px;
    }
    
    .warning {
        color: #ffaa00;
        border: 1px solid #ffaa00;
        padding: 1rem;
        border-radius: 4px;
    }
    
    .critical {
        color: #ff4444;
        border: 1px solid #ff4444;
        padding: 1rem;
        border-radius: 4px;
    }
    
    .port-result, .header-item, .security-item {
        padding: 0.5rem;
        margin: 0.25rem 0;
        border-left: 3px solid;
    }
    
    .port-result.critical, .security-item.warning {
        border-left-color: #ff4444;
        background: rgba(255, 68, 68, 0.1);
    }
    
    .port-result.warning, .security-item.warning {
        border-left-color: #ffaa00;
        background: rgba(255, 170, 0, 0.1);
    }
    
    .port-result.safe, .security-item.safe {
        border-left-color: #00ff00;
        background: rgba(0, 255, 0, 0.1);
    }
    
    .risk-tag {
        font-size: 0.8rem;
        padding: 0.2rem 0.5rem;
        border-radius: 3px;
        margin-left: 0.5rem;
    }
    
    .disclaimer {
        font-size: 0.8rem;
        color: #888;
        margin-top: 1rem;
        font-style: italic;
    }
`;
document.head.appendChild(toolStyles);
