// organization.js - Terrifying Organization Page
console.log('👁️ Bedusec Organization System Initialized');

let subscriptionData = JSON.parse(localStorage.getItem('bedusec_subscriptions')) || [];

document.addEventListener('DOMContentLoaded', function() {
    initializeOrganization();
    startCyberEffects();
});

function initializeOrganization() {
    // Add terrifying effects
    addTerrifyingElements();
    
    // Update subscription counts
    updateSubscriptionStats();
    
    // Start random security alerts
    startSecurityAlerts();
}

function addTerrifyingElements() {
    // Add random security scan effects
    setInterval(() => {
        const scans = ['SECURITY_SCAN_COMPLETE', 'THREAT_ANALYSIS_ACTIVE', 'INTRUSION_DETECTED'];
        const randomScan = scans[Math.floor(Math.random() * scans.length)];
        console.log(`🔍 ${randomScan}`);
    }, 10000);

    // Add creepy terminal messages
    const messages = [
        'Multiple intrusion attempts detected...',
        'Tracking 12 active threats...',
        'Zero-day vulnerability research in progress...',
        'Encrypted communications established...',
        'Shadow operations active...'
    ];

    setInterval(() => {
        const randomMsg = messages[Math.floor(Math.random() * messages.length)];
        addTerminalMessage(randomMsg);
    }, 15000);
}

function addTerminalMessage(message) {
    const terminal = document.querySelector('.subscription-terminal');
    if (terminal) {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="output">${message}</span>`;
        terminal.querySelector('.subscription-form').before(line);
        
        // Keep only last 5 messages
        const lines = terminal.querySelectorAll('.terminal-line');
        if (lines.length > 8) {
            lines[3].remove(); // Remove old messages but keep initial ones
        }
    }
}

function startCyberEffects() {
    // Add random glitch effects
    setInterval(() => {
        const glitchElements = document.querySelectorAll('.glitch');
        glitchElements.forEach(el => {
            if (Math.random() > 0.7) {
                el.style.animation = 'glitch-1 0.3s infinite linear alternate-reverse';
                setTimeout(() => {
                    el.style.animation = 'none';
                }, 300);
            }
        });
    }, 5000);

    // Add particle effects on hover
    document.querySelectorAll('.access-card').forEach(card => {
        card.addEventListener('mouseenter', function() {
            createParticles(this);
        });
    });
}

function createParticles(element) {
    const rect = element.getBoundingClientRect();
    for (let i = 0; i < 5; i++) {
        setTimeout(() => {
            const particle = document.createElement('div');
            particle.style.cssText = `
                position: fixed;
                width: 2px;
                height: 2px;
                background: #ff0080;
                border-radius: 50%;
                pointer-events: none;
                z-index: 10000;
                left: ${rect.left + Math.random() * rect.width}px;
                top: ${rect.top + Math.random() * rect.height}px;
                animation: particleFloat 1s ease-out forwards;
            `;
            
            document.body.appendChild(particle);
            
            setTimeout(() => particle.remove(), 1000);
        }, i * 100);
    }
}

function subscribe(tier) {
    const tierNames = {
        'observer': 'Observer',
        'operative': 'Operative', 
        'shadow': 'Shadow'
    };
    
    const tierPrices = {
        'observer': 0,
        'operative': 99,
        'shadow': 499
    };

    showSubscriptionModal(tierNames[tier], tierPrices[tier], tier);
}

function showSubscriptionModal(tierName, price, tierLevel) {
    // Create terrifying subscription modal
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.95);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        backdrop-filter: blur(10px);
    `;
    
    modal.innerHTML = `
        <div style="
            background: rgba(0, 20, 0, 0.95);
            border: 2px solid #ff0080;
            border-radius: 8px;
            padding: 2rem;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 0 50px rgba(255, 0, 128, 0.5);
            position: relative;
            overflow: hidden;
        ">
            <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
                background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 0, 128, 0.1) 2px, rgba(255, 0, 128, 0.1) 4px);
                animation: matrix 10s linear infinite; pointer-events: none;">
            </div>
            
            <div style="position: relative; z-index: 2;">
                <h3 style="color: #ff0080; text-align: center; margin-bottom: 1rem;">
                    <i class="fas fa-skull"></i> ACCESS REQUEST: ${tierName.toUpperCase()}
                </h3>
                
                <div style="background: rgba(255, 0, 128, 0.1); border: 1px solid #ff0080; border-radius: 4px; padding: 1rem; margin: 1rem 0;">
                    <p style="color: #ff88cc; text-align: center; margin: 0;">
                        <strong>Warning:</strong> This action will flag your profile for enhanced monitoring
                    </p>
                </div>
                
                ${price > 0 ? `
                <div style="text-align: center; margin: 1.5rem 0;">
                    <span style="font-size: 2rem; color: #00ff00; font-weight: bold;">$${price}</span>
                    <span style="color: #88ff88;">/month</span>
                </div>
                ` : ''}
                
                <div style="display: flex; gap: 1rem; justify-content: center; margin-top: 2rem;">
                    <button onclick="confirmSubscription('${tierLevel}')" style="
                        background: linear-gradient(45deg, #ff0080, #ff3399);
                        color: white;
                        border: none;
                        padding: 1rem 2rem;
                        border-radius: 4px;
                        font-family: 'Share Tech Mono', monospace;
                        font-weight: bold;
                        cursor: pointer;
                    ">
                        <i class="fas fa-check"></i> CONFIRM
                    </button>
                    
                    <button onclick="this.closest('div').parentElement.parentElement.remove()" style="
                        background: transparent;
                        color: #88ff88;
                        border: 1px solid #88ff88;
                        padding: 1rem 2rem;
                        border-radius: 4px;
                        font-family: 'Share Tech Mono', monospace;
                        cursor: pointer;
                    ">
                        <i class="fas fa-times"></i> ABORT
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

function confirmSubscription(tier) {
    // Remove modal
    document.querySelector('div[style*="position: fixed"]').remove();
    
    // Show processing message
    showAlert('Processing access request... Enhanced background check initiated', 'warning');
    
    // Simulate processing delay
    setTimeout(() => {
        // Save subscription
        const subscription = {
            id: Date.now(),
            tier: tier,
            date: new Date().toISOString(),
            status: 'pending',
            clearance: generateClearanceCode()
        };
        
        subscriptionData.push(subscription);
        localStorage.setItem('bedusec_subscriptions', JSON.stringify(subscriptionData));
        
        // Show success message
        showAlert(`ACCESS GRANTED - Clearance Level: ${subscription.clearance}`, 'success');
        
        // Update stats
        updateSubscriptionStats();
        
        // Add to terminal
        addTerminalMessage(`New ${tier} access granted: ${subscription.clearance}`);
        
    }, 3000);
}

function processSubscription() {
    const name = document.getElementById('subName').value;
    const email = document.getElementById('subEmail').value;
    const level = document.getElementById('subLevel').value;
    const message = document.getElementById('subMessage').value;
    const agreed = document.getElementById('subAgree').checked;
    
    if (!name || !email || !agreed) {
        showAlert('Complete all fields and accept security terms', 'error');
        return;
    }
    
    showAlert('Encrypting transmission... Stand by', 'info');
    
    // Simulate secure transmission
    setTimeout(() => {
        const submission = {
            id: Date.now(),
            name: name,
            email: email,
            level: level,
            message: message,
            timestamp: new Date().toISOString(),
            ip: 'REDACTED',
            status: 'under_review'
        };
        
        // Save to local storage (in real implementation, send to backend)
        let submissions = JSON.parse(localStorage.getItem('bedusec_access_requests')) || [];
        submissions.push(submission);
        localStorage.setItem('bedusec_access_requests', JSON.stringify(submissions));
        
        showAlert('Access request transmitted securely. Await clearance.', 'success');
        
        // Reset form
        document.getElementById('subName').value = '';
        document.getElementById('subEmail').value = '';
        document.getElementById('subMessage').value = '';
        document.getElementById('subAgree').checked = false;
        
        // Add to terminal
        addTerminalMessage(`Access request received from: ${name}`);
        
    }, 2000);
}

function generateClearanceCode() {
    const prefixes = ['SHADOW', 'PHANTOM', 'GHOST', 'SPECTRE', 'WRAITH'];
    const numbers = Math.floor(1000 + Math.random() * 9000);
    return `${prefixes[Math.floor(Math.random() * prefixes.length)]}-${numbers}`;
}

function updateSubscriptionStats() {
    const observerCount = subscriptionData.filter(s => s.tier === 'observer').length;
    const operativeCount = subscriptionData.filter(s => s.tier === 'operative').length;
    const shadowCount = subscriptionData.filter(s => s.tier === 'shadow').length;
    
    console.log(`📊 Subscriptions - Observer: ${observerCount}, Operative: ${operativeCount}, Shadow: ${shadowCount}`);
}

function startSecurityAlerts() {
    const alerts = [
        'Unauthorized access attempt blocked',
        'Firewall integrity confirmed',
        'Encryption protocols active',
        'Threat database updated',
        'Secure channel verified'
    ];
    
    setInterval(() => {
        if (Math.random() > 0.8) {
            const alert = alerts[Math.floor(Math.random() * alerts.length)];
            console.log(`🚨 ${alert}`);
        }
    }, 20000);
}

function showAlert(message, type = 'info') {
    const alert = document.createElement('div');
    alert.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(0, 30, 0, 0.95);
        border: 1px solid;
        border-radius: 4px;
        padding: 1rem 1.5rem;
        color: ;
        z-index: 10001;
        font-family: 'Share Tech Mono', monospace;
        animation: slideInRight 0.3s ease;
        max-width: 400px;
    `;
    
    if (type === 'error') {
        alert.style.borderColor = '#ff0080';
        alert.style.color = '#ff0080';
    } else if (type === 'success') {
        alert.style.borderColor = '#00ff00';
        alert.style.color = '#00ff00';
    } else if (type === 'warning') {
        alert.style.borderColor = '#ffaa00';
        alert.style.color = '#ffaa00';
    } else {
        alert.style.borderColor = '#0088ff';
        alert.style.color = '#0088ff';
    }
    
    alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'exclamation-triangle' : 'info'}"></i>
        ${message}
    `;
    
    document.body.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

// Add CSS for new animations
const style = document.createElement('style');
style.textContent = `
    @keyframes particleFloat {
        0% {
            transform: translateY(0) scale(1);
            opacity: 1;
        }
        100% {
            transform: translateY(-100px) scale(0);
            opacity: 0;
        }
    }
    
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    .toggle-label {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: #88ff88;
        font-size: 0.9rem;
        margin: 1rem 0;
        cursor: pointer;
    }
    
    .toggle-label input[type="checkbox"] {
        display: none;
    }
    
    .toggle-slider {
        width: 40px;
        height: 20px;
        background: rgba(255, 255, 255, 0.2);
        border-radius: 10px;
        position: relative;
        transition: all 0.3s ease;
    }
    
    .toggle-slider::before {
        content: '';
        position: absolute;
        width: 16px;
        height: 16px;
        background: #ffffff;
        border-radius: 50%;
        top: 2px;
        left: 2px;
        transition: all 0.3s ease;
    }
    
    .toggle-label input[type="checkbox"]:checked + .toggle-slider {
        background: #00ff00;
    }
    
    .toggle-label input[type="checkbox"]:checked + .toggle-slider::before {
        transform: translateX(20px);
    }
`;
document.head.appendChild(style);

console.log('🔐 Bedusec Organization System - Operational');
console.log('💀 Welcome to the shadow organization...');
