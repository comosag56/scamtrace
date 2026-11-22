import { chromium } from 'playwright';
import crypto from 'crypto';
import fs from 'fs';

export async function capture(url) {
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36',
      viewport: { width: 390, height: 844 },
      acceptDownloads: false,
      ignoreHTTPSErrors: true,
    });

    const page = await ctx.newPage();
    const hops = [];

    // Track navigation redirects while ignoring background image/script noise
    page.on('response', r => {
      const s = r.status();
      if (s >= 300 && s < 400 && r.request().isNavigationRequest()) {
        hops.push({ url: r.url(), status: s, to: r.headers()['location'] });
      }
    });

    page.on('framenavigated', f => {
      if (f === page.mainFrame()) {
        const currentUrl = f.url();
        const lastHop = hops[hops.length - 1];
        if (!lastHop || lastHop.url !== currentUrl) {
          hops.push({ url: currentUrl, type: 'navigation' });
        }
      }
    });

    try {
      await page.goto(url, { waitUntil: 'load', timeout: 15000 });
      await page.waitForTimeout(1500);
    } catch (navErr) {
      console.warn(`[Sandbox Warning] Navigation timeout or error: ${navErr.message}`);
    }

    const finalUrl = page.url();
    const shot = await page.screenshot({ fullPage: true });
    const html = await page.content();

    const fields = await page.$$eval('input', els =>
      els.map(e => ({ type: e.type, name: e.name, placeholder: e.placeholder }))
    );

    const sha = b => crypto.createHash('sha256').update(b).digest('hex');
    const shotSha = sha(shot);
    const htmlSha = sha(html);

    fs.mkdirSync('evidence', { recursive: true });
    const timestamp = Date.now();
    const shotPath = `evidence/${timestamp}_shot.png`;
    fs.writeFileSync(shotPath, shot);
    fs.writeFileSync('evidence/shot.png', shot);

    return {
      finalUrl,
      hops,
      fields,
      shotPath,
      shotSha,
      htmlSha,
    };
  } finally {
    // Guarantees Chromium never leaks as a zombie process
    await browser.close();
  }
}
