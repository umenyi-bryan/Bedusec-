// Load chatbot component
fetch('ai-chatbot.html')
    .then(response => response.text())
    .then(html => {
        document.getElementById('chatbotContainer').innerHTML = html;
    })
    .catch(error => {
        console.error('Error loading chatbot:', error);
    });
