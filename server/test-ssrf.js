import { assertSafe } from './ssrf.js';
import { capture } from './capture.js';

async function runSsrfTests() {
  console.log('--- ScamTrace SSRF Guard Rail Verification ---');

  const testCases = [
    { url: 'http://127.0.0.1', shouldPass: false, label: 'Localhost IPv4' },
    { url: 'http://169.254.169.254', shouldPass: false, label: 'Cloud Metadata IP (AWS/GCP)' },
    { url: 'http://192.168.1.1', shouldPass: false, label: 'Private LAN Class C' },
    { url: 'http://10.0.0.5', shouldPass: false, label: 'Private LAN Class A' },
    { url: 'http://0.0.0.0', shouldPass: false, label: 'Default route 0.0.0.0' },
    { url: 'file:///etc/passwd', shouldPass: false, label: 'Local File Scheme' },
    { url: 'https://example.com', shouldPass: true, label: 'Legitimate Public HTTPS URL' }
  ];

  let passedAll = true;

  for (const tc of testCases) {
    try {
      await assertSafe(tc.url);
      if (!tc.shouldPass) {
        console.error(`❌ FAILED: ${tc.label} (${tc.url}) should have been BLOCKED but passed!`);
        passedAll = false;
      } else {
        console.log(`✅ PASSED: ${tc.label} (${tc.url}) successfully allowed.`);
      }
    } catch (err) {
      if (!tc.shouldPass) {
        console.log(`✅ PASSED: ${tc.label} (${tc.url}) correctly rejected: "${err.message}"`);
      } else {
        console.error(`❌ FAILED: ${tc.label} (${tc.url}) should have passed but threw: "${err.message}"`);
        passedAll = false;
      }
    }
  }

  // Verify that capture() rejects before launching browser
  console.log('\nTesting capture() integration with http://127.0.0.1:');
  try {
    await capture('http://127.0.0.1');
    console.error('❌ FAILED: capture() did not block http://127.0.0.1');
    passedAll = false;
  } catch (err) {
    console.log(`✅ PASSED: capture() safely aborted with: "${err.message}"`);
  }

  console.log('\nTesting capture() integration with http://169.254.169.254:');
  try {
    await capture('http://169.254.169.254');
    console.error('❌ FAILED: capture() did not block http://169.254.169.254');
    passedAll = false;
  } catch (err) {
    console.log(`✅ PASSED: capture() safely aborted with: "${err.message}"`);
  }

  if (!passedAll) {
    process.exit(1);
  }
}

runSsrfTests().catch(err => {
  console.error('Unexpected test error:', err);
  process.exit(1);
});
