const { GoogleGenerativeAI } = require('@google/generative-ai');

exports.handler = async (event) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        const { url, code, type } = JSON.parse(event.body);
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

        let prompt = '';
        
        if (type === 'website') {
            prompt = `Analyze this website URL for security vulnerabilities: ${url}. 
            Provide a detailed security assessment including:
            1. Potential vulnerabilities
            2. Security recommendations
            3. Risk level assessment
            4. Immediate actions to take`;
        } else if (type === 'code') {
            prompt = `Analyze this code for security vulnerabilities: ${code}
            Provide:
            1. Vulnerability analysis
            2. Code security issues
            3. Fix recommendations
            4. Security best practices`;
        }

        const model = genAI.getGenerativeModel({ model: "gemini-pro" });
        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                analysis: text,
                timestamp: new Date().toISOString(),
                type: type
            })
        };

    } catch (error) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Analysis failed: ' + error.message })
        };
    }
};
