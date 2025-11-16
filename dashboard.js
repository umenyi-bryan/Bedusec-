// dashboard.js - Bedusec Admin Command Center
document.addEventListener('DOMContentLoaded', function() {
    console.log('🔐 Bedusec Command Center Initialized');
    
    // Update live date and time
    function updateDateTime() {
        const now = new Date();
        const options = { 
            weekday: 'long', 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false 
        };
        
        const dateTimeString = now.toLocaleDateString('en-US', options) + ' UTC';
        document.getElementById('liveDateTime').textContent = dateTimeString.toUpperCase();
    }
    
    // Update immediately and then every second
    updateDateTime();
    setInterval(updateDateTime, 1000);
    
    // Tab navigation functionality
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');
    
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all items and contents
            navItems.forEach(nav => nav.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Show corresponding tab content
            const tabId = this.getAttribute('data-tab');
            const targetTab = document.getElementById(tabId);
            if (targetTab) {
                targetTab.classList.add('active');
            }
        });
    });
    
    // Terminal simulation
    const terminalOutput = document.getElementById('terminalOutput');
    let terminalInterval;
    
    const terminalLines = [
        'Starting comprehensive vulnerability scan...',
        'Scanning network range: 192.168.1.0/24',
        'Discovered 4 active hosts',
        'Host 192.168.1.1:22 - SSH (OpenSSH 8.2)',
        'Host 192.168.1.5:80 - HTTP (Apache 2.4.41)',
        'Host 192.168.1.5:443 - HTTPS (TLS 1.3)',
        'Host 192.168.1.10:3389 - RDP (Windows)',
        'Running service enumeration...',
        'Performing vulnerability assessment...',
        'Checking for known CVEs...',
        'CVE-2023-1234 detected - Critical severity',
        'CVE-2023-5678 detected - High severity',
        'Generating security report...',
        'Scan completed. 2 critical vulnerabilities found.'
    ];
    
    let lineIndex = 0;
    
    function addTerminalLine() {
        if (lineIndex < terminalLines.length) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">[root@bedusec]#</span> ${terminalLines[lineIndex]}`;
            terminalOutput.appendChild(line);
            lineIndex++;
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        } else {
            clearInterval(terminalInterval);
            // Add blinking cursor
            const cursorLine = document.createElement('div');
            cursorLine.className = 'terminal-line';
            cursorLine.innerHTML = `<span class="prompt">[root@bedusec]#</span> <span class="cursor">|</span>`;
            terminalOutput.appendChild(cursorLine);
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
        }
    }
    
    // Terminal controls
    document.getElementById('termPlay').addEventListener('click', function() {
        clearInterval(terminalInterval);
        lineIndex = 0;
        terminalOutput.innerHTML = '';
        terminalInterval = setInterval(addTerminalLine, 800);
    });
    
    document.getElementById('termStop').addEventListener('click', function() {
        clearInterval(terminalInterval);
    });
    
    document.getElementById('termClear').addEventListener('click', function() {
        terminalOutput.innerHTML = '';
        lineIndex = 0;
    });
    
    // Start terminal simulation after a short delay
    setTimeout(() => {
        terminalInterval = setInterval(addTerminalLine, 800);
    }, 2000);
    
    // Tool buttons functionality
    const toolButtons = document.querySelectorAll('.tool-btn');
    toolButtons.forEach(button => {
        button.addEventListener('click', function() {
            const toolName = this.querySelector('span').textContent;
            const toolType = this.getAttribute('data-tool');
            
            // Add to terminal
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">[root@bedusec]#</span> Initializing ${toolName}...`;
            terminalOutput.appendChild(line);
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            
            // Visual feedback
            const originalBg = this.style.background;
            const originalColor = this.style.color;
            const originalBorder = this.style.borderColor;
            
            this.style.background = 'rgba(0, 255, 0, 0.3)';
            this.style.color = '#00ff00';
            this.style.borderColor = '#00ff00';
            
            // Simulate tool execution
            setTimeout(() => {
                const resultLine = document.createElement('div');
                resultLine.className = 'terminal-line';
                
                switch(toolType) {
                    case 'network-scan':
                        resultLine.innerHTML = `<span class="output">${toolName}: Found 8 active hosts, 2 open ports per host</span>`;
                        break;
                    case 'web-crawler':
                        resultLine.innerHTML = `<span class="output">${toolName}: Crawled 124 pages, found 3 forms</span>`;
                        break;
                    case 'vuln-scanner':
                        resultLine.innerHTML = `<span class="output">${toolName}: Scanned 45 endpoints, 2 vulnerabilities detected</span>`;
                        break;
                    case 'generate-report':
                        resultLine.innerHTML = `<span class="output">${toolName}: Security report generated (bedusec_report_${Date.now()}.pdf)</span>`;
                        break;
                    default:
                        resultLine.innerHTML = `<span class="output">${toolName}: Operation completed successfully</span>`;
                }
                
                terminalOutput.appendChild(resultLine);
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            }, 1500);
            
            setTimeout(() => {
                this.style.background = originalBg;
                this.style.color = originalColor;
                this.style.borderColor = originalBorder;
            }, 2000);
        });
    });
    
    // System stats animation
    function animateStats() {
        const stats = document.querySelectorAll('.stat-number');
        stats.forEach(stat => {
            const target = parseInt(stat.getAttribute('data-target'));
            const duration = 2000;
            const step = target / (duration / 16);
            let current = 0;
            
            const timer = setInterval(() => {
                current += step;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                stat.textContent = Math.floor(current);
            }, 16);
        });
    }
    
    // Start stats animation
    setTimeout(animateStats, 1000);
    
    // Simulate live alerts
    function simulateAlert() {
        const activityFeed = document.querySelector('.activity-feed');
        const alerts = [
            {
                type: 'critical',
                icon: 'fas fa-user-secret',
                title: 'Suspicious Login Attempt - Multiple Failures',
                time: 'Just now'
            },
            {
                type: 'warning',
                icon: 'fas fa-shield-alt',
                title: 'Firewall Rules Updated - New Restrictions Applied',
                time: '2 minutes ago'
            },
            {
                type: 'safe',
                icon: 'fas fa-check',
                title: 'System Backup Completed - All Data Secured',
                time: '5 minutes ago'
            }
        ];
        
        alerts.forEach((alert, index) => {
            setTimeout(() => {
                const alertItem = document.createElement('div');
                alertItem.className = `activity-item ${alert.type}`;
                alertItem.innerHTML = `
                    <div class="activity-icon">
                        <i class="${alert.icon}"></i>
                    </div>
                    <div class="activity-content">
                        <span class="activity-title">${alert.title}</span>
                        <span class="activity-time">${alert.time}</span>
                    </div>
                `;
                
                activityFeed.insertBefore(alertItem, activityFeed.firstChild);
                
                // Update alert counter for critical alerts only
                if (alert.type === 'critical') {
                    const alertIndicator = document.querySelector('.alert-indicator span');
                    const currentCount = parseInt(alertIndicator.textContent.split(': ')[1]);
                    alertIndicator.textContent = `CRITICAL: ${currentCount + 1}`;
                    
                    // Flash the alert indicator
                    alertIndicator.parentElement.style.animation = 'pulse 0.5s 3';
                    setTimeout(() => {
                        alertIndicator.parentElement.style.animation = '';
                    }, 1500);
                }
                
            }, (index + 1) * 8000); // 8 seconds between alerts
        });
    }
    
    // Start alert simulation
    setTimeout(simulateAlert, 10000);
    
    // Lock system functionality
    document.getElementById('lockSystem').addEventListener('click', function() {
        this.innerHTML = '<i class="fas fa-lock"></i> SYSTEM LOCKED';
        this.style.background = 'linear-gradient(45deg, #ff0000, #ff6666)';
        
        // Simulate system lock
        const lockLine = document.createElement('div');
        lockLine.className = 'terminal-line';
        lockLine.innerHTML = `<span class="prompt">[root@bedusec]#</span> <span style="color: #ff0000;">SYSTEM LOCKDOWN INITIATED - ALL ACCESS SUSPENDED</span>`;
        terminalOutput.appendChild(lockLine);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
        
        // Disable all interactive elements
        const interactiveElements = document.querySelectorAll('button, .nav-item, .tool-btn');
        interactiveElements.forEach(el => {
            el.style.opacity = '0.5';
            el.style.pointerEvents = 'none';
        });
        
        // Show lock screen after delay
        setTimeout(() => {
            const lockScreen = document.createElement('div');
            lockScreen.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.95);
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                color: #ff0000;
                font-family: 'Share Tech Mono', monospace;
                text-align: center;
            `;
            
            lockScreen.innerHTML = `
                <div style="font-size: 4rem; margin-bottom: 2rem;">
                    <i class="fas fa-lock"></i>
                </div>
                <h1 style="font-size: 2.5rem; margin-bottom: 1rem; text-shadow: 0 0 10px #ff0000;">SYSTEM LOCKED</h1>
                <p style="font-size: 1.2rem; color: #ff6666; margin-bottom: 2rem;">BEDUSEC SECURITY PROTOCOL ENGAGED</p>
                <p style="font-size: 1rem; color: #888; max-width: 500px; line-height: 1.6;">
                    All systems secured. Unauthorized access attempts will be logged and reported.
                    <br>Authorized personnel only.
                </p>
                <button onclick="location.reload()" style="
                    background: #ff0000;
                    color: white;
                    border: none;
                    padding: 1rem 2rem;
                    font-family: 'Share Tech Mono', monospace;
                    font-size: 1.1rem;
                    margin-top: 2rem;
                    cursor: pointer;
                    border-radius: 4px;
                ">
                    <i class="fas fa-unlock"></i> UNLOCK SYSTEM
                </button>
            `;
            
            document.body.appendChild(lockScreen);
        }, 2000);
    });
    
    // Real-time system monitoring simulation
    function simulateSystemMonitoring() {
        setInterval(() => {
            // Randomly update CPU usage
            const cpuBars = document.querySelectorAll('.progress-fill');
            if (cpuBars.length > 0) {
                const currentWidth = parseInt(cpuBars[0].style.width);
                const newWidth = Math.max(20, Math.min(90, currentWidth + (Math.random() * 20 - 10)));
                cpuBars[0].style.width = `${newWidth}%`;
            }
            
            // Occasionally add random terminal activity
            if (Math.random() > 0.7) {
                const randomActivities = [
                    'Network traffic analysis: 245 MB/s inbound, 189 MB/s outbound',
                    'Security log: 12 new entries in last 60 seconds',
                    'Memory usage stable at 42% capacity',
                    'Database queries: 1,245 processed in last minute',
                    'Firewall: Blocked 3 suspicious IP addresses',
                    'IDS: No new threats detected in last 5 minutes'
                ];
                
                const randomActivity = randomActivities[Math.floor(Math.random() * randomActivities.length)];
                const activityLine = document.createElement('div');
                activityLine.className = 'terminal-line';
                activityLine.innerHTML = `<span class="output" style="color: #888;">${randomActivity}</span>`;
                terminalOutput.appendChild(activityLine);
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            }
        }, 5000);
    }
    
    // Start system monitoring
    setTimeout(simulateSystemMonitoring, 5000);
    
    // Add cyber sound effects (visual)
    function createCyberParticle(x, y) {
        const particle = document.createElement('div');
        particle.style.cssText = `
            position: fixed;
            width: 4px;
            height: 4px;
            background: #00ff00;
            border-radius: 50%;
            pointer-events: none;
            z-index: 10000;
            left: ${x}px;
            top: ${y}px;
            animation: cyberParticle 1s ease-out forwards;
            box-shadow: 0 0 10px #00ff00;
        `;
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes cyberParticle {
                0% {
                    transform: scale(1);
                    opacity: 1;
                }
                50% {
                    transform: scale(2);
                    opacity: 0.5;
                }
                100% {
                    transform: scale(0);
                    opacity: 0;
                }
            }
        `;
        
        if (!document.querySelector('style[data-cyber-particles]')) {
            style.setAttribute('data-cyber-particles', 'true');
            document.head.appendChild(style);
        }
        
        document.body.appendChild(particle);
        
        setTimeout(() => {
            particle.remove();
        }, 1000);
    }
    
    // Add cyber effects to dashboard interactions
    const dashboardElements = document.querySelectorAll('.tool-btn, .ctrl-btn, .cyber-btn, .nav-item');
    dashboardElements.forEach(element => {
        element.addEventListener('click', function(e) {
            createCyberParticle(e.clientX, e.clientY);
        });
    });
    
    // Initialize dashboard
    console.log('✅ Bedusec Command Center fully operational');
    console.log('📊 System monitoring active');
    console.log('🔒 Security protocols engaged');
});
