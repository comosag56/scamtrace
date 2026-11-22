import net from 'net';

const TWO_PART_TLDS = new Set([
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au',
  'com.br', 'co.nz'
]);

/**
 * Extracts the registrable root/apex domain from a URL or hostname.
 * Examples:
 *   "https://login.secure.fake-bank.co.in/pay" -> "fake-bank.co.in"
 *   "scam.xyz" -> "scam.xyz"
 *   "www.google.com" -> "google.com"
 */
export function extractApexDomain(rawInput) {
  let hostname = rawInput.trim();
  try {
    if (hostname.includes('://')) {
      hostname = new URL(hostname).hostname;
    } else {
      hostname = new URL(`http://${hostname}`).hostname;
    }
  } catch {
    // Keep as-is if URL parsing fails
  }

  hostname = hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
  const parts = hostname.split('.');
  if (parts.length <= 2) {
    return hostname;
  }

  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo)) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

/**
 * Queries RDAP for registration data.
 */
async function queryRdap(domain) {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const res = await fetch(url, {
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'ScamTrace-Forensics/1.0 (https://github.com/comosag56/scamtrace; security-triage)'
    },
    signal: AbortSignal.timeout(8000)
  });

  if (!res.ok) {
    throw new Error(`RDAP returned HTTP ${res.status}`);
  }

  const data = await res.json();
  const regEvent = data.events?.find(e => 
    e.eventAction === 'registration' || 
    e.eventAction === 'created' || 
    e.eventAction === 'transfer'
  );

  if (!regEvent?.eventDate) {
    throw new Error('Registration eventDate not found in RDAP response');
  }

  return {
    registeredAt: new Date(regEvent.eventDate).toISOString(),
    source: 'rdap.org'
  };
}

/**
 * Fallback TCP WHOIS query (Port 43)
 */
function queryWhoisFallback(domain) {
  const tld = domain.split('.').pop();
  let server = 'whois.verisign-grs.com';
  if (tld === 'in') server = 'whois.inregistry.net';
  else if (tld === 'org') server = 'whois.publicinterestregistry.org';

  return new Promise((resolve, reject) => {
    const socket = net.createConnection(43, server, () => {
      socket.write(`${domain}\r\n`);
    });

    let data = '';
    socket.on('data', chunk => { data += chunk; });
    socket.on('end', () => {
      const match = data.match(/(?:Creation Date|Created On|Registration Time):\s*(.+)/i);
      if (match && match[1]) {
        const parsed = new Date(match[1].trim());
        if (!isNaN(parsed.getTime())) {
          return resolve({ registeredAt: parsed.toISOString(), source: `whois://${server}` });
        }
      }
      reject(new Error('Registration date not parsable from WHOIS output'));
    });

    socket.on('error', reject);
    socket.setTimeout(6000, () => {
      socket.destroy();
      reject(new Error(`WHOIS connection timed out to ${server}`));
    });
  });
}

/**
 * Main entry point: Gets domain age in days and registration date with fallback.
 * 
 * @param {string} urlOrDomain - URL string or domain name
 * @returns {Promise<{ domain: string, registeredAt: string, ageInDays: number, isFresh: boolean, source: string }>}
 */
export async function getDomainAge(urlOrDomain) {
  const domain = extractApexDomain(urlOrDomain);
  let regData = null;

  // 1. Try modern RDAP first
  try {
    regData = await queryRdap(domain);
  } catch (rdapErr) {
    // 2. Fallback to WHOIS
    try {
      regData = await queryWhoisFallback(domain);
    } catch (whoisErr) {
      throw new Error(`Failed to retrieve registration date for ${domain}: RDAP (${rdapErr.message}), WHOIS (${whoisErr.message})`);
    }
  }

  const regDate = new Date(regData.registeredAt);
  const diffMs = Date.now() - regDate.getTime();
  const ageInDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

  return {
    domain,
    registeredAt: regData.registeredAt,
    ageInDays,
    isFresh: ageInDays < 30, // Domains under 30 days old are high scam risk
    source: regData.source
  };
}
