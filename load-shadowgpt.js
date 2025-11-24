// Load ShadowGPT component
fetch('shadowgpt-chatbot.html')
    .then(response => response.text())
    .then(html => {
        document.getElementById('shadowGPTContainer').innerHTML = html;
        console.log('🤖 ShadowGPT loaded and ready for pentesting queries');
    })
    .catch(error => {
        console.error('Error loading ShadowGPT:', error);
    });
