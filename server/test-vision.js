import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeScreenshot } from './vision.js';
import { capture } from './capture.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runVisionTest() {
  console.log('--- ScamTrace Test 2: Vision Model Verification (Groq Llama 3.2 Vision) ---');

  const shotPath = path.resolve(__dirname, '../evidence/shot.png');

  // Ensure shot.png exists; if not, capture the mock fixture first
  if (!fs.existsSync(shotPath)) {
    console.log('evidence/shot.png not found, capturing demo fixture first...');
    const fixturePath = path.resolve(__dirname, '../demo-pages/mock-upi-scam.html');
    await capture(`file://${fixturePath.replace(/\\/g, '/')}`, { allowLocalFixtures: true });
  }

  console.log(`Analyzing screenshot: ${shotPath}`);
  const startTime = Date.now();
  
  const result = await analyzeScreenshot(shotPath);
  const elapsed = Date.now() - startTime;

  console.log(`\nVision analysis completed in ${elapsed}ms:`);
  console.log(JSON.stringify(result, null, 2));

  // Verification checks for Test 2 pass condition
  if (!result || typeof result !== 'object') {
    throw new Error('Test failed: Result is not a valid JSON object');
  }
  if (typeof result.impersonated_brand !== 'string') {
    throw new Error('Test failed: impersonated_brand is missing or not a string');
  }
  if (!Array.isArray(result.asks_for)) {
    throw new Error('Test failed: asks_for is missing or not an array');
  }
  if (!Array.isArray(result.urgency_cues)) {
    throw new Error('Test failed: urgency_cues is missing or not an array');
  }
  if (typeof result.confidence !== 'number') {
    throw new Error('Test failed: confidence is missing or not a number');
  }

  console.log('\n✅ PASS: Received clean, structured forensic JSON from Groq Vision model!');
}

runVisionTest().catch(err => {
  console.error('\n❌ Test 2 Failed:', err);
  process.exit(1);
});
