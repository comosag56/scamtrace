import { getDomainAge, extractApexDomain } from './domain-age.js';

async function runDomainAgeTests() {
  console.log('--- ScamTrace Test 4: Domain Age Verification (RDAP + WHOIS Fallback) ---');

  // Test TLDs planned for demo (.com, .xyz, .in, and .co.in)
  const testDomains = [
    { target: 'google.com', expectedTld: '.com' },
    { target: 'abc.xyz', expectedTld: '.xyz' },
    { target: 'flipkart.in', expectedTld: '.in' },
    { target: 'https://secure-login.test.sbi.co.in/otp', expectedTld: '.co.in' },
  ];

  let allPassed = true;

  for (const item of testDomains) {
    console.log(`\nChecking domain age for: ${item.target} (TLD: ${item.expectedTld})`);
    try {
      const start = Date.now();
      const res = await getDomainAge(item.target);
      const elapsed = Date.now() - start;

      console.log(`  -> Resolved Apex Domain: ${res.domain}`);
      console.log(`  -> Registration Date:    ${res.registeredAt}`);
      console.log(`  -> Domain Age:            ${res.ageInDays} days (~${(res.ageInDays / 365).toFixed(1)} years)`);
      console.log(`  -> Fresh Scam Alert:     ${res.isFresh ? '🚨 HIGH RISK (< 30 days)' : '✅ Established Domain'}`);
      console.log(`  -> Data Source:          ${res.source} (${elapsed}ms)`);

      if (!res.registeredAt || isNaN(new Date(res.registeredAt).getTime())) {
        console.error(`  ❌ FAIL: Invalid registration date for ${item.target}`);
        allPassed = false;
      }
    } catch (err) {
      console.error(`  ❌ FAIL: Could not resolve ${item.target}: ${err.message}`);
      allPassed = false;
    }
  }

  if (allPassed) {
    console.log('\n✅ PASS: Successfully retrieved valid registration dates across .com, .xyz, and .in!');
  } else {
    process.exit(1);
  }
}

runDomainAgeTests().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});
