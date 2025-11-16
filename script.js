// script.js - Main Site Functionality
document.addEventListener('DOMContentLoaded', function() {
    // Typing effect for terminal
    const typedText = document.querySelector('.typed-command');
    const cursor = document.querySelector('.cursor');
    
    const commands = [
        'start_penetration_test --target=client_system',
        'analyze_vulnerabilities --level=critical',
        'generate_security_report --format=pdf',
        'initiate_secure_session --encryption=aes256'
    ];
    
    let commandIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    
    function type() {
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
    
    // Start typing effect
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
});
