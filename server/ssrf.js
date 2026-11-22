import dns from 'dns/promises';
import net from 'net';

const blocked = new net.BlockList();
for (const [ip, bits] of [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['0.0.0.0', 8]
]) {
  blocked.addSubnet(ip, bits);
}

export async function assertSafe(rawUrl) {
  const u = new URL(rawUrl);
  if (!['http:', 'https:'].includes(u.protocol)) {
    throw new Error(`bad protocol: ${u.protocol}`);
  }

  // Handle direct IP addresses and domain names
  const addrs = await dns.lookup(u.hostname, { all: true });
  for (const a of addrs) {
    if (a.family === 6) {
      throw new Error('ipv6 not allowed in MVP');
    }
    if (blocked.check(a.address, 'ipv4')) {
      throw new Error(`blocked address: ${a.address} (${u.hostname})`);
    }
  }
}
