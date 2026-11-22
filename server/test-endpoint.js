import { app } from './index.js';

async function runEndpointTest() {
  console.log('--- ScamTrace Endpoint Verification (POST /api/investigate) ---');

  const server = app.listen(3005);
  const baseUrl = 'http://localhost:3005';

  try {
    // Test 1: Health check
    console.log('\n1. Testing GET /health...');
    const healthRes = await fetch(`${baseUrl}/health`);
    const healthData = await healthRes.json();
    console.log(`   -> Status: ${healthRes.status}, Response:`, healthData);
    if (healthRes.status !== 200) throw new Error('Health check failed');

    // Test 2: Missing URL validation
    console.log('\n2. Testing POST /api/investigate with empty body...');
    const emptyRes = await fetch(`${baseUrl}/api/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    console.log(`   -> Status: ${emptyRes.status} (Expected: 400)`);
    if (emptyRes.status !== 400) throw new Error('Expected 400 for empty body');

    // Test 3: SSRF blocked address
    console.log('\n3. Testing POST /api/investigate with SSRF payload (http://127.0.0.1)...');
    const ssrfRes = await fetch(`${baseUrl}/api/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1' })
    });
    const ssrfData = await ssrfRes.json();
    console.log(`   -> Status: ${ssrfRes.status} (Expected: 400), Error: "${ssrfData.error}"`);
    if (ssrfRes.status !== 400 || !ssrfData.error) throw new Error('SSRF blocking failed');

    console.log('\n✅ PASS: Endpoint correctly validates inputs, enforces SSRF, and serves API routes!');
  } finally {
    server.close();
  }
}

runEndpointTest().catch(err => {
  console.error('\n❌ Endpoint Test Failed:', err);
  process.exit(1);
});
