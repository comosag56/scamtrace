/**
 * Known legitimate domains for common impersonated entities (demo brands).
 */
const OFFICIAL_DOMAINS = {
  'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'statebankofindia.com'],
  'electricity board': ['bescom.karnataka.gov.in', 'bescom.org', 'kptcl.karnataka.gov.in'],
  'bescom': ['bescom.karnataka.gov.in', 'bescom.org'],
  'india post': ['indiapost.gov.in'],
  'income tax': ['incometax.gov.in']
};

/**
 * Calculates a deterministic risk score (0 - 100) and human-readable evidence reasons.
 * 
 * Rules decide the score; the vision and sandbox models provide the forensic signals.
 * 
 * @param {Object} params
 * @param {Object} [params.domain] - Domain age and RDAP data
 * @param {Object} [params.capture] - Playwright sandbox capture data (fields, hops, finalUrl)
 * @param {Object} [params.vision] - Vision model analysis (impersonated_brand, urgency_cues, confidence)
 * @returns {{ score: number, level: 'CRITICAL' | 'SUSPICIOUS' | 'LOW', reasons: string[] }}
 */
export function scoreRisk({ domain = {}, capture = {}, vision = {} } = {}) {
  let score = 0;
  const reasons = [];

  // Rule 1: Fresh domain registration (< 30 days)
  if (typeof domain?.ageInDays === 'number' && domain.ageInDays < 30) {
    score += 30;
    reasons.push(`Website domain is brand new (only ${domain.ageInDays} days old)`);
  }

  // Rule 2: Credential harvesting in form inputs
  const sensitive = (capture?.fields || []).filter(f =>
    /pass|pin|otp|card|cvv|upi/i.test(`${f.type || ''} ${f.name || ''} ${f.placeholder || ''}`)
  );
  if (sensitive.length > 0) {
    score += 25;
    reasons.push('Asks for highly sensitive financial credentials (PIN, OTP, Card, or UPI details)');
  }

  // Rule 3: Cloaking through multi-hop redirect chains
  const hopCount = (capture?.hops || []).length;
  if (hopCount >= 3) {
    score += 10;
    reasons.push(`Unusual redirection chain (${hopCount} hops before landing on final page)`);
  }

  // Rule 4: Brand impersonation vs domain mismatch
  if (vision?.impersonated_brand && (vision.confidence ?? 0) >= 0.6) {
    const rawBrand = vision.impersonated_brand.toLowerCase().trim();
    let hostname = '';
    try {
      if (capture?.finalUrl) {
        hostname = new URL(capture.finalUrl).hostname.toLowerCase();
      }
    } catch {
      // URL parsing fallback
    }

    // Check official domain whitelist if available
    const officialList = OFFICIAL_DOMAINS[rawBrand] || [];
    const isOfficial = officialList.some(d => hostname === d || hostname.endsWith(`.${d}`));

    if (!isOfficial) {
      const sanitizedHost = hostname.replace(/[^a-z0-9]/g, '');
      const sanitizedBrand = rawBrand.replace(/[^a-z0-9]/g, '');

      if (!sanitizedHost.includes(sanitizedBrand) || sanitizedBrand.length === 0) {
        score += 25;
        reasons.push(`Visually impersonates "${vision.impersonated_brand}", but the web address (${hostname || 'unverified'}) does not match`);
      }
    }
  }

  // Rule 5: Coercive psychological urgency cues
  if (Array.isArray(vision?.urgency_cues) && vision.urgency_cues.length > 0) {
    score += 10;
    reasons.push(`Uses psychological pressure/threats (${vision.urgency_cues.slice(0, 2).join('; ')})`);
  }

  // Clamp score between 0 and 100
  score = Math.min(100, Math.max(0, score));

  // Determine threat severity level
  const level = score >= 70 ? 'CRITICAL' : score >= 40 ? 'SUSPICIOUS' : 'LOW';

  return { score, level, reasons };
}
