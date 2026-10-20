// OpenX Pro license validation — POST {key} -> {valid:boolean}
// Key types:
//  - OX1-...          manual HMAC keys (secret from env PRO_SECRET)
//  - UUID (LS format) Lemon Squeezy license keys -> proxied to LS license API
const crypto = require('crypto');
const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += ALPH[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += ALPH[(val << (5 - bits)) & 31];
  return out;
}
function b32dec(str) {
  let bits = 0, val = 0; const out = [];
  for (const ch of str) { val = (val << 5) | ALPH.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function isValidOX1(key, secret) {
  const m = /^OX1-([A-Z2-7]{8})-([A-Z2-7]{8})$/.exec(key || '');
  if (!m || !secret) return false;
  const expected = b32enc(crypto.createHmac('sha256', secret).update(b32dec(m[1])).digest().subarray(0, 5));
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(m[2])); }
  catch (e) { return false; }
}
async function isValidLS(key) {
  try {
    const r = await fetch('https://app.lemonsqueezy.com/api/v1/licenses/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({ license_key: key }).toString(),
    });
    const j = await r.json();
    return !!(j && j.valid === true);
  } catch (e) { return false; }
}
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(200).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ valid: false }); return; }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  const raw = ((body && body.key) || '').trim();
  let valid = false;
  if (/^OX1-/i.test(raw)) {
    valid = isValidOX1(raw.toUpperCase(), (process.env.PRO_SECRET || '').trim());
  } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) {
    valid = await isValidLS(raw);
  }
  res.status(200).json({ valid });
};
