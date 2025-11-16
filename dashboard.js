// dashboard.js - Admin Dashboard Functionality
document.addEventListener('DOMContentLoaded', function() {
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
        document.getElementById('liveDateTime').textContent = dateTimeString;
    }
    
    // Update immediately and then every second
    updateDateTime();
    setInterval(updateDateTime, 1000);
    
    // Terminal simulation
    const terminalLines = [
        'Starting vulnerability scan on target network...',
        'Scanning ports 1-65535...',
        'Discovered 4 active hosts',
        'Host 192.168.1.1:22 - SSH (OpenSSH 8.2)',
        'Host 192.168.1.5:80 - HTTP (Apache 2.4.41)',
        'Host 192.168.1.5:443 - HTTPS',
        'Running service enumeration...',
        'Scan completed. 2 potential vulnerabilities found.'
    ];
    
    let lineIndex = 0;
    const terminalOutput = document.querySelector('.terminal-output');
    
    function addTerminalLine() {
        if (lineIndex < terminalLines.length) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.textContent = terminalLines[lineIndex];
            terminalOutput.appendChild(line);
            lineIndex++;
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            
            // Random delay between lines for realism
            const delay = Math.random() * 1000 + 500;
            setTimeout(addTerminalLine, delay);
        }
    }
    
    // Start terminal simulation after a short delay
    setTimeout(addTerminalLine, 2000);
    
    // Navigation active state
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Tool buttons functionality
    const toolButtons = document.querySelectorAll('.tool-btn');
    toolButtons.forEach(button => {
        button.addEventListener('click', function() {
            const toolName = this.querySelector('span').textContent;
            
            // Add to terminal
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">[root@bedusec]#</span> Starting ${toolName}...`;
            terminalOutput.appendChild(line);
            terminalOutput.scrollTop = terminalOutput.scrollHeight;
            
            // Visual feedback
            this.style.background = 'rgba(0, 255, 0, 0.3)';
            this.style.color = '#00ff00';
            this.style.borderColor = '#00ff00';
            
            setTimeout(() => {
                this.style.background = '';
                this.style.color = '';
                this.style.borderColor = '';
            }, 1000);
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
                type: 'warning',
                icon: 'fas fa-user-secret',
                title: 'Suspicious Login Attempt',
                time: 'Just now'
            },
            {
                type: 'safe',
                icon: 'fas fa-shield-alt',
                title: 'Firewall Rules Updated',
                time: 'Just now'
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
                
                // Update alert counter
                const alertIndicator = document.querySelector('.alert-indicator span');
                const currentCount = parseInt(alertIndicator.textContent.split(': ')[1]);
                alertIndicator.textContent = `CRITICAL: ${currentCount + (alert.type === 'critical' ? 1 : 0)}`;
                
            }, (index + 1) * 5000);
        });
    }
    
    // Start alert simulation
    setTimeout(simulateAlert, 10000);
});
