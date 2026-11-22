import 'dotenv/config';
import fs from 'fs';
import { Groq } from 'groq-sdk';

// Pool of Groq API keys for automatic failover and rate-limit rotation
const apiKeys = [
  process.env.GROQ_API_KEY_1,
  process.env.GROQ_API_KEY_2,
  process.env.GROQ_API_KEY_3,
  process.env.GROQ_API_KEY,
].filter((k, idx, arr) => k && arr.indexOf(k) === idx);

let currentKeyIndex = 0;

function getNextGroqClient() {
  if (apiKeys.length === 0) {
    throw new Error('No GROQ_API_KEY found in environment or .env file');
  }
  const key = apiKeys[currentKeyIndex % apiKeys.length];
  currentKeyIndex = (currentKeyIndex + 1) % apiKeys.length;
  return new Groq({ apiKey: key });
}

/**
 * Analyzes a screenshot of a suspicious web page using Groq Multimodal Vision.
 * 
 * @param {string|Buffer} png - File path string or raw image Buffer
 * @returns {Promise<{ impersonated_brand: string, asks_for: string[], urgency_cues: string[], confidence: number }>}
 */
export async function analyzeScreenshot(png) {
  let imageBuffer;
  if (typeof png === 'string') {
    if (!fs.existsSync(png)) {
      throw new Error(`Screenshot file not found: ${png}`);
    }
    imageBuffer = fs.readFileSync(png);
  } else if (Buffer.isBuffer(png)) {
    imageBuffer = png;
  } else {
    throw new Error('Invalid input: png must be a file path string or Buffer');
  }

  const base64Image = imageBuffer.toString('base64');
  const dataUrl = `data:image/png;base64,${base64Image}`;

  const prompt = `You are an expert digital forensics and cyber fraud triage analyst.
Analyze this screenshot of a suspected scam/phishing web page.

You MUST return ONLY a valid JSON object with these exact keys:
{
  "impersonated_brand": "<Name of company, bank, government agency, or utility being spoofed, or 'Unknown'/'None'>",
  "asks_for": ["<list of sensitive inputs requested, e.g. 'UPI PIN', 'Password', 'OTP', 'Credit Card', 'Phone Number'>"],
  "urgency_cues": ["<list of psychological urgency/fear cues, e.g. 'Disconnection tonight', 'Urgent notice', 'Immediate action'>"],
  "confidence": <float between 0.0 and 1.0 indicating confidence this is a scam or phishing attempt>
}`;

  let lastError = null;
  const attempts = Math.max(apiKeys.length, 1);

  // Attempt across available keys in rotation pool
  for (let i = 0; i < attempts; i++) {
    const groq = getNextGroqClient();
    try {
      const completion = await groq.chat.completions.create({
        model: 'qwen/qwen3.8-27b',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: prompt },
              {
                type: 'image_url',
                image_url: { url: dataUrl },
              },
            ],
          },
        ],
        response_format: { type: 'json_object' },
        temperature: 0.1,
      });

      const rawContent = completion.choices[0]?.message?.content;
      if (!rawContent) {
        throw new Error('Groq returned an empty response');
      }

      const parsed = JSON.parse(rawContent);

      return {
        impersonated_brand: parsed.impersonated_brand || 'Unknown',
        asks_for: Array.isArray(parsed.asks_for) ? parsed.asks_for : [],
        urgency_cues: Array.isArray(parsed.urgency_cues) ? parsed.urgency_cues : [],
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.9,
      };
    } catch (err) {
      console.warn(`[Groq Vision Warning] Key attempt ${i + 1}/${attempts} failed: ${err.message}. Rotating...`);
      lastError = err;
    }
  }

  throw new Error(`All Groq API key attempts failed: ${lastError?.message}`);
}
