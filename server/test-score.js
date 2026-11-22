import { scoreRisk } from './score.js';

async function runScoreTests() {
  console.log('--- ScamTrace Risk Scoring Engine Verification ---');

  // Test Case 1: Blatant Phishing Attack (Mock electricity bill / UPI fraud)
  const phishingCase = {
    domain: { ageInDays: 2 },
    capture: {
      finalUrl: 'http://power-bill-payment.xyz/login.php',
      fields: [
        { type: 'text', name: 'consumer_id', placeholder: 'Consumer No' },
        { type: 'password', name: 'upi_pin', placeholder: 'Enter UPI PIN to verify' }
      ],
      hops: [{ url: 'http://bit.ly/123' }, { url: 'http://redirect.link' }, { url: 'http://power-bill-payment.xyz' }]
    },
    vision: {
      impersonated_brand: 'Electricity Board',
      confidence: 0.95,
      urgency_cues: ['POWER DISCONNECTION Tonight 9:30 PM', 'Pay immediately']
    }
  };

  const result1 = scoreRisk(phishingCase);
  console.log('\n[Scenario 1: Full Phishing Site]');
  console.log(`  -> Score:   ${result1.score}/100`);
  console.log(`  -> Level:   ${result1.level}`);
  console.log('  -> Reasons:');
  result1.reasons.forEach(r => console.log(`     • ${r}`));

  if (result1.score < 70 || result1.level !== 'CRITICAL') {
    throw new Error(`Scenario 1 failed: Expected CRITICAL (>= 70), got ${result1.score} (${result1.level})`);
  }

  // Test Case 2: Legitimate Established Site
  const legitCase = {
    domain: { ageInDays: 8500 },
    capture: {
      finalUrl: 'https://bescom.karnataka.gov.in',
      fields: [{ type: 'text', name: 'search', placeholder: 'Search website...' }],
      hops: [{ url: 'https://bescom.karnataka.gov.in' }]
    },
    vision: {
      impersonated_brand: 'Electricity Board',
      confidence: 0.8,
      urgency_cues: []
    }
  };

  const result2 = scoreRisk(legitCase);
  console.log('\n[Scenario 2: Legitimate Official Site]');
  console.log(`  -> Score:   ${result2.score}/100`);
  console.log(`  -> Level:   ${result2.level}`);
  console.log(`  -> Reasons: ${result2.reasons.length ? result2.reasons.join(', ') : 'None (clean)'}`);

  if (result2.level !== 'LOW') {
    throw new Error(`Scenario 2 failed: Expected LOW, got ${result2.score} (${result2.level})`);
  }

  // Test Case 3: Suspicious Site (established domain but asks for sensitive PIN/OTP)
  const suspiciousCase = {
    domain: { ageInDays: 400 },
    capture: {
      finalUrl: 'https://some-unrelated-blog.com/form',
      fields: [{ type: 'password', name: 'pin', placeholder: 'Enter ATM PIN' }],
      hops: []
    },
    vision: {
      impersonated_brand: 'Unknown',
      confidence: 0.2,
      urgency_cues: []
    }
  };

  const result3 = scoreRisk(suspiciousCase);
  console.log('\n[Scenario 3: Suspicious Form on Older Domain]');
  console.log(`  -> Score:   ${result3.score}/100`);
  console.log(`  -> Level:   ${result3.level}`);

  console.log('\n✅ PASS: Risk scoring engine correctly evaluates forensic signals into deterministic threat tiers!');
}

runScoreTests().catch(err => {
  console.error('\n❌ Test Failed:', err);
  process.exit(1);
});
