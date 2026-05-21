const https = require('https');
const fs = require('fs');
const path = require('path');

class LlmService {
    static async generate(model, prompt) {
        return new Promise((resolve, reject) => {
            let apiKey;
            try {
                apiKey = fs.readFileSync(path.join(__dirname, 'key.txt'), 'utf8').trim();
            } catch (err) {
                return reject(new Error("Failed to read key.txt. Please ensure your API key is in key.txt."));
            }

            // Groq uses OpenAI-compatible endpoints
            const data = JSON.stringify({
                model: 'llama-3.1-8b-instant', // Map default to groq model
                messages: [
                    { role: "user", content: prompt }
                ],
                temperature: 0.5,
                max_tokens: 2048,
                stream: false
            });

            const options = {
                hostname: 'api.groq.com',
                path: '/openai/v1/chat/completions',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Length': Buffer.byteLength(data)
                }
            };

            const req = https.request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(responseData);
                        if (parsed.error) {
                            return reject(new Error("Groq API Error: " + parsed.error.message));
                        }
                        if (parsed.choices && parsed.choices.length > 0) {
                            resolve(parsed.choices[0].message.content);
                        } else {
                            reject(new Error("Unexpected response format from Groq."));
                        }
                    } catch (e) {
                        reject(new Error("Invalid JSON from Groq: " + responseData));
                    }
                });
            });

            req.on('error', (error) => {
                console.error('Groq connection error:', error);
                reject(error);
            });

            req.write(data);
            req.end();
        });
    }
}

module.exports = LlmService;
