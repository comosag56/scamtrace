import 'dotenv/config';
import express from 'express';
import { assertSafe } from './ssrf.js';
import { capture } from './capture.js';
import { analyzeScreenshot } from './vision.js';
import { getDomainAge } from './domain-age.js';
import { scoreRisk } from './score.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ScamTrace API' });
});

app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // 1. SSRF Validation
    await assertSafe(url);

    // 2. Headless Sandbox Detonation & Capture
    const captureResult = await capture(url);

    // 3. Vision Model Analysis
    const visionResult = await analyzeScreenshot(captureResult.shotPath);

    // 4. Domain Age Resolution
    let domainData = null;
    try {
      domainData = await getDomainAge(url);
    } catch (dErr) {
      domainData = { error: dErr.message };
    }

    // 5. Deterministic Risk Scoring
    const risk = scoreRisk({
      domain: domainData,
      capture: captureResult,
      vision: visionResult
    });

    res.json({
      success: true,
      url,
      risk,
      capture: captureResult,
      vision: visionResult,
      domain: domainData,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`ScamTrace server listening on http://localhost:${PORT}`);
});
