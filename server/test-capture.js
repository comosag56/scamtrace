import { capture } from './capture.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runTest() {
  console.log('--- ScamTrace Sandbox Capture Test ---');
  
  // Test with local demo fixture
  const fixturePath = path.resolve(__dirname, '../demo-pages/mock-upi-scam.html');
  const testUrl = `file://${fixturePath.replace(/\\/g, '/')}`;

  console.log(`Testing capture on fixture: ${testUrl}`);
  const startTime = Date.now();
  
  const result = await capture(testUrl);
  const elapsed = Date.now() - startTime;

  console.log(`\nCapture completed in ${elapsed}ms:`);
  console.log('Final URL:', result.finalUrl);
  console.log('Hops captured:', result.hops.length);
  console.log('Extracted Form Fields:');
  result.fields.forEach(f => console.log(`  - [${f.type}] name="${f.name}" placeholder="${f.placeholder}"`));
  console.log('Screenshot SHA-256:', result.shotSha);
  console.log('HTML DOM SHA-256:', result.htmlSha);
  console.log('Saved Screenshot:', result.shotPath);
}

runTest().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
