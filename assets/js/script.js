// script.js - Bedusec Main Site Functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Bedusec Security Platform Initialized');
    
    // Typing effect for terminal
    const typedText = document.querySelector('.typed-command');
    const cursor = document.querySelector('.cursor');
    
    const commands = [
        'start_penetration_test --target=client_system',
        'analyze_vulnerabilities --level=critical',
        'generate_security_report --format=pdf',
        'initiate_secure_session --encryption=aes256',
        'scan_network --subnet=192.168.1.0/24',
        'monitor_intrusion_detection --real-time'
    ];
    
    let commandIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let isPaused = false;
    
    function type() {
        if (isPaused) return;
        
        const currentCommand = commands[commandIndex];
        
        if (isDeleting) {
            // Deleting text
            typedText.textContent = currentCommand.substring(0, charIndex - 1);
            charIndex--;
        } else {
            // Typing text
            typedText.textContent = currentCommand.substring(0, charIndex + 1);
            charIndex++;
        }
        
        // Set type speed
        let typeSpeed = isDeleting ? 50 : 100;
        
        // If word is complete
        if (!isDeleting && charIndex === currentCommand.length) {
            typeSpeed = 2000; // Pause at end
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            commandIndex = (commandIndex + 1) % commands.length;
            typeSpeed = 500; // Pause before next word
        }
        
        setTimeout(type, typeSpeed);
    }
    
    // Start typing effect after a delay
    setTimeout(type, 1000);
    
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Add glitch effect to section titles on hover
    const glitchTitles = document.querySelectorAll('.glitch');
    glitchTitles.forEach(title => {
        title.addEventListener('mouseenter', function() {
            this.style.animation = 'glitch-1 0.3s infinite linear alternate-reverse';
        });
        
        title.addEventListener('mouseleave', function() {
            this.style.animation = 'none';
        });
    });
    
    // Matrix background enhancement
    function enhanceMatrixBackground() {
        const matrixBg = document.querySelector('.matrix-bg');
        if (!matrixBg) return;
        
        // Add additional matrix effect
        const additionalEffect = document.createElement('div');
        additionalEffect.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                90deg,
                transparent,
                transparent 50px,
                rgba(0, 255, 0, 0.02) 50px,
                rgba(0, 255, 0, 0.02) 100px
            );
            animation: matrixHorizontal 25s linear infinite;
            pointer-events: none;
        `;
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes matrixHorizontal {
                0% { transform: translateX(0); }
                100% { transform: translateX(-100px); }
            }
        `;
        
        document.head.appendChild(style);
        matrixBg.appendChild(additionalEffect);
    }
    
    enhanceMatrixBackground();
    
    // Service card animations
    const serviceCards = document.querySelectorAll('.service-card');
    serviceCards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.2}s`;
        card.classList.add('fade-in-up');
    });
    
    // Add CSS for fade-in animation
    const animationStyles = document.createElement('style');
    animationStyles.textContent = `
        .fade-in-up {
            animation: fadeInUp 0.6s ease-out forwards;
            opacity: 0;
            transform: translateY(30px);
        }
        
        @keyframes fadeInUp {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .tool-item {
            animation: pulseGlow 2s ease-in-out infinite alternate;
        }
        
        @keyframes pulseGlow {
            from {
                box-shadow: 0 0 5px rgba(0, 136, 255, 0.3);
            }
            to {
                box-shadow: 0 0 20px rgba(0, 136, 255, 0.6);
            }
        }
    `;
    document.head.appendChild(animationStyles);
    
    // Contact form handling
    const contactForm = document.querySelector('.contact-form');
    if (contactForm) {
        const cyberButton = contactForm.querySelector('.cyber-button');
        const cyberInput = contactForm.querySelector('.cyber-input');
        const cyberTextarea = contactForm.querySelector('.cyber-textarea');
        
        cyberButton.addEventListener('click', function(e) {
            e.preventDefault();
            
            if (!cyberInput.value.trim() || !cyberTextarea.value.trim()) {
                // Show error effect
                cyberButton.style.background = '#ff0000';
                cyberButton.textContent = 'ERROR: FILL ALL FIELDS';
                setTimeout(() => {
                    cyberButton.style.background = '';
                    cyberButton.innerHTML = '<i class="fas fa-paper-plane"></i> SEND ENCRYPTED';
                }, 2000);
                return;
            }
            
            // Simulate sending
            cyberButton.style.background = '#00ff00';
            cyberButton.innerHTML = '<i class="fas fa-lock"></i> ENCRYPTING & SENDING...';
            
            setTimeout(() => {
                cyberButton.style.background = '#0088ff';
                cyberButton.innerHTML = '<i class="fas fa-check"></i> MESSAGE SENT SECURELY';
                
                // Reset form
                cyberInput.value = '';
                cyberTextarea.value = '';
                
                // Reset button after delay
                setTimeout(() => {
                    cyberButton.style.background = '';
                    cyberButton.innerHTML = '<i class="fas fa-paper-plane"></i> SEND ENCRYPTED';
                }, 3000);
            }, 2000);
        });
    }
    
    // Add parallax effect to matrix background
    window.addEventListener('scroll', function() {
        const scrolled = window.pageYOffset;
        const matrixBg = document.querySelector('.matrix-bg');
        if (matrixBg) {
            matrixBg.style.transform = `translateY(${scrolled * 0.5}px)`;
        }
    });
    
    // Tool items hover effects
    const toolItems = document.querySelectorAll('.tool-item');
    toolItems.forEach(item => {
        item.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.15) rotate(2deg)';
            this.style.zIndex = '10';
        });
        
        item.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1) rotate(0deg)';
            this.style.zIndex = '1';
        });
    });
    
    // Terminal window drag effect (visual only)
    const terminalWindow = document.querySelector('.terminal-window');
    if (terminalWindow) {
        let isDragging = false;
        let startX, startY, initialX, initialY;
        
        terminalWindow.addEventListener('mousedown', startDrag);
        terminalWindow.addEventListener('touchstart', startDrag);
        
        function startDrag(e) {
            isDragging = true;
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const clientY = e.touches ? e.touches[0].clientY : e.clientY;
            
            startX = clientX;
            startY = clientY;
            initialX = terminalWindow.offsetLeft;
            initialY = terminalWindow.offsetTop;
            
            document.addEventListener('mousemove', drag);
            document.addEventListener('touchmove', drag);
            document.addEventListener('mouseup', stopDrag);
            document.addEventListener('touchend', stopDrag);
            
            terminalWindow.style.transition = 'none';
            terminalWindow.style.cursor = 'grabbing';
        }
        
        function drag(e) {
            if (!isDragging) return;
            
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const clientY = e.touches ? e.touches[0].clientY : e.clientY;
            
            const deltaX = clientX - startX;
            const deltaY = clientY - startY;
            
            terminalWindow.style.left = `${initialX + deltaX}px`;
            terminalWindow.style.top = `${initialY + deltaY}px`;
        }
        
        function stopDrag() {
            isDragging = false;
            document.removeEventListener('mousemove', drag);
            document.removeEventListener('touchmove', drag);
            document.removeEventListener('mouseup', stopDrag);
            document.removeEventListener('touchend', stopDrag);
            
            terminalWindow.style.transition = 'all 0.3s ease';
            terminalWindow.style.cursor = 'grab';
            
            // Snap back to center with smooth animation
            setTimeout(() => {
                terminalWindow.style.left = '';
                terminalWindow.style.top = '';
            }, 100);
        }
        
        // Make terminal window draggable on desktop
        terminalWindow.style.cursor = 'grab';
    }
    
    // Add cyber sound effects (visual feedback)
    function createRippleEffect(x, y) {
        const ripple = document.createElement('div');
        ripple.style.cssText = `
            position: fixed;
            width: 20px;
            height: 20px;
            background: radial-gradient(circle, rgba(0, 255, 0, 0.6) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            z-index: 10000;
            left: ${x - 10}px;
            top: ${y - 10}px;
            animation: rippleEffect 0.6s ease-out forwards;
        `;
        
        const style = document.createElement('style');
        style.textContent = `
            @keyframes rippleEffect {
                0% {
                    transform: scale(1);
                    opacity: 1;
                }
                100% {
                    transform: scale(4);
                    opacity: 0;
                }
            }
        `;
        
        document.head.appendChild(style);
        document.body.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    }
    
    // Add click effects to cyber elements
    const cyberElements = document.querySelectorAll('.cyber-button, .nav-link, .service-card, .tool-item');
    cyberElements.forEach(element => {
        element.addEventListener('click', function(e) {
            createRippleEffect(e.clientX, e.clientY);
        });
    });
    
    // Initialize everything
    console.log('✅ Bedusec platform fully operational');
});
