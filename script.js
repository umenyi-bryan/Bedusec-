// Bedusec Main JavaScript - Terminal Animations and Interactions

document.addEventListener('DOMContentLoaded', function() {
    // Terminal typing animation
    initTerminalAnimation();
    
    // Smooth scrolling for navigation links
    initSmoothScrolling();
    
    // Service card animations
    initServiceAnimations();
    
    // Tool scroller enhancements
    initToolScroller();
});

function initTerminalAnimation() {
    const typedElement = document.querySelector('.typed-command');
    if (!typedElement) return;
    
    const commands = [
        'start_security_scan',
        'analyze_vulnerabilities', 
        'initiate_penetration_test',
        'deploy_countermeasures',
        'secure_systems',
        'protect_assets'
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
            typedElement.textContent = currentCommand.substring(0, charIndex - 1);
            charIndex--;
        } else {
            // Typing text
            typedElement.textContent = currentCommand.substring(0, charIndex + 1);
            charIndex++;
        }
        
        if (!isDeleting && charIndex === currentCommand.length) {
            // Finished typing, pause then start deleting
            isPaused = true;
            setTimeout(() => {
                isPaused = false;
                isDeleting = true;
                setTimeout(type, 100);
            }, 2000);
        } else if (isDeleting && charIndex === 0) {
            // Finished deleting, move to next command
            isDeleting = false;
            commandIndex = (commandIndex + 1) % commands.length;
            setTimeout(type, 500);
        } else {
            // Continue typing/deleting
            setTimeout(type, isDeleting ? 50 : 100);
        }
    }
    
    // Start the animation after a delay
    setTimeout(type, 1000);
}

function initSmoothScrolling() {
    const navLinks = document.querySelectorAll('a[href^="#"]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                const offsetTop = targetElement.offsetTop - 80; // Account for fixed nav
                
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });
}

function initServiceAnimations() {
    const serviceCards = document.querySelectorAll('.service-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    serviceCards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(card);
    });
}

function initToolScroller() {
    const scroller = document.querySelector('.tools-scroller');
    if (!scroller) return;
    
    let isDown = false;
    let startX;
    let scrollLeft;
    
    scroller.addEventListener('mousedown', (e) => {
        isDown = true;
        scroller.classList.add('active');
        startX = e.pageX - scroller.offsetLeft;
        scrollLeft = scroller.scrollLeft;
    });
    
    scroller.addEventListener('mouseleave', () => {
        isDown = false;
        scroller.classList.remove('active');
    });
    
    scroller.addEventListener('mouseup', () => {
        isDown = false;
        scroller.classList.remove('active');
    });
    
    scroller.addEventListener('mousemove', (e) => {
        if (!isDown) return;
        e.preventDefault();
        const x = e.pageX - scroller.offsetLeft;
        const walk = (x - startX) * 2;
        scroller.scrollLeft = scrollLeft - walk;
    });
}

// Cyberpunk text effect for headings
function initCyberpunkText() {
    const cyberpunkElements = document.querySelectorAll('.glitch');
    
    cyberpunkElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            this.style.animation = 'glitch-1 0.5s infinite linear alternate-reverse';
        });
        
        element.addEventListener('mouseleave', function() {
            this.style.animation = 'none';
        });
    });
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initTerminalAnimation();
    initSmoothScrolling();
    initServiceAnimations();
    initToolScroller();
    initCyberpunkText();
});

// Utility function for dynamic content loading
function loadContent(url, containerId) {
    fetch(url)
        .then(response => response.text())
        .then(data => {
            document.getElementById(containerId).innerHTML = data;
        })
        .catch(error => {
            console.error('Error loading content:', error);
        });
}

// Security notification system
function showSecurityAlert(message, level = 'info') {
    const alert = document.createElement('div');
    alert.className = `security-alert ${level}`;
    alert.innerHTML = `
        <div class="alert-content">
            <i class="fas fa-shield-alt"></i>
            <span>${message}</span>
            <button class="alert-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    document.body.appendChild(alert);
    
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 5000);
}
