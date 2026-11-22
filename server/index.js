import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import { assertSafe } from './ssrf.js';
import { capture } from './capture.js';
import { analyzeScreenshot } from './vision.js';
import { getDomainAge } from './domain-age.js';
import { scoreRisk } from './score.js';

export const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('web'));
app.use('/evidence', express.static('evidence'));

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ScamTrace API' });
});

async function handleInvestigation(req, res) {
  const t0 = Date.now();
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // 1. SSRF Security Gate
    await assertSafe(url);

    // 2. Headless Sandbox Detonation
    const cap = await capture(url);

    // 3. Parallel Execution: Groq Multimodal Vision + RDAP Domain Age
    const png = fs.readFileSync(cap.shotPath ?? 'evidence/shot.png');
    const [vision, domain] = await Promise.all([
      analyzeScreenshot(png).catch(e => ({ error: e.message })),
      getDomainAge(cap.finalUrl).catch(e => ({ error: e.message })),
    ]);

    // 4. Deterministic Risk Evaluation
    const risk = scoreRisk({ domain, capture: cap, vision });

    // 5. Return Forensic Dossier
    res.json({
      url,
      capture: cap,
      vision,
      domain,
      risk,
      ms: Date.now() - t0,
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
}

app.post('/api/investigate', handleInvestigation);
app.post('/api/scan', handleInvestigation); // Backwards-compatible alias

if (process.argv[1]?.endsWith('index.js')) {
  app.listen(PORT, () => {
    console.log(`ScamTrace server listening on http://localhost:${PORT}`);
  });
}
