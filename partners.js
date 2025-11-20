// partners.js - Partnerships Page
console.log('🤝 Bedusec Partnerships Loaded');

document.addEventListener('DOMContentLoaded', function() {
    loadPartners();
});

async function loadPartners() {
    try {
        const response = await fetch('data/database.json');
        const data = await response.json();
        displayPartners(data.partners);
    } catch (error) {
        console.error('Error loading partners:', error);
        document.getElementById('partnersGrid').innerHTML = '<div class="error">Failed to load partners</div>';
    }
}

function displayPartners(partners) {
    const partnersGrid = document.getElementById('partnersGrid');
    
    if (!partners || partners.length === 0) {
        partnersGrid.innerHTML = `
            <div class="empty-partners">
                <i class="fas fa-handshake fa-3x"></i>
                <h3>No Partners Yet</h3>
                <p>We're actively seeking strategic partnerships in cybersecurity</p>
            </div>
        `;
        return;
    }
    
    partnersGrid.innerHTML = partners.map(partner => `
        <div class="partner-card ${partner.featured ? 'featured' : ''}">
            <div class="partner-logo">
                <img src="${partner.logo}" alt="${partner.name}" 
                     onerror="this.src='https://via.placeholder.com/200x100/00ff00/000000?text=${encodeURIComponent(partner.name)}'">
                ${partner.featured ? '<span class="featured-badge">FEATURED</span>' : ''}
            </div>
            <div class="partner-info">
                <h3>${partner.name}</h3>
                <p>${partner.description}</p>
                <div class="partner-meta">
                    <span class="join-date">Partner since ${partner.joined}</span>
                </div>
            </div>
            <div class="partner-actions">
                <a href="${partner.website}" target="_blank" class="cyber-button small">
                    <i class="fas fa-external-link-alt"></i> Visit
                </a>
            </div>
        </div>
    `).join('');
}

function submitPartnership() {
    const name = document.getElementById('partnerName').value;
    const email = document.getElementById('partnerEmail').value;
    const proposal = document.getElementById('partnerProposal').value;
    
    if (!name || !email || !proposal) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    // Simulate form submission
    showNotification('Partnership proposal submitted successfully! We will contact you soon.', 'success');
    
    // Reset form
    document.getElementById('partnerName').value = '';
    document.getElementById('partnerEmail').value = '';
    document.getElementById('partnerProposal').value = '';
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : 'exclamation-triangle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}
