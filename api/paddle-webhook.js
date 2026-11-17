// Paddle webhook -> mint an OpenX Pro licence key (OX1) and email it to the buyer.
// Vercel serverless function. Deploy with the showcase repo (api/paddle-webhook.js).
//
// Env vars (set in the Vercel dashboard, never in code):
//   PADDLE_WEBHOOK_SECRET - notification destination secret (pdl_ntfset_...)
//   PADDLE_API_KEY        - server-side API key (resolves customer email from customer_id)
//   PRO_SECRET            - same HMAC secret as api/pro/validate.js (already set)
//   RESEND_API_KEY        - Resend API key for sending the key email (free tier is fine)
//   KEY_FROM_EMAIL        - sender, e.g. "OpenX Pro <pro@openx-mo.vercel.app>" (optional)
//
// How keys work (same as pro-keys/keygen.js, no database needed):
//   key = OX1-<base32(id 5 bytes)>-<base32(HMAC-SHA256(PRO_SECRET, id)[0:5])>
//   The id is derived deterministically from the purchase, so Paddle retries and
//   subscription renewals mint the SAME key instead of a new one each time:
//     subscription purchase/renewal -> id = SHA256("sub:" + subscription_id)[0:5]
//     one-time (Lifetime) purchase  -> id = SHA256("txn:" + transaction_id)[0:5]
//   api/pro/validate.js already validates OX1 keys with PRO_SECRET, unchanged.
//
// Known v1 limits (be honest about them):
//   - A cancelled subscription's key keeps validating until a status check is
//     built (needs key->subscription mapping storage). Refunds/cancellations
//     are logged here for manual handling.
//   - The key is derivable from the Paddle transaction/subscription id, which
//     only the buyer (via their receipt) and Paddle know. Treat as equivalent
//     to "whoever holds the receipt holds the key".
//   - If the email step is not configured, the key is only written to the
//     Vercel function logs. Register the webhook destination only after the
//     env vars above are set.
const crypto = require('crypto');

const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += ALPH[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += ALPH[(val << (5 - bits)) & 31];
  return out;
}

function mintKeyFor(ref, secret) {
  const id = crypto.createHash('sha256').update(ref).digest().subarray(0, 5);
  const sig = crypto.createHmac('sha256', secret).update(id).digest().subarray(0, 5);
  return `OX1-${b32enc(id)}-${b32enc(sig)}`;
}

// Paddle-Signature header: "ts=<unix seconds>;h1=<hex hmac>".
// Signature = HMAC-SHA256(webhookSecret, ts + ":" + rawBody).
function verifySignature(rawBody, header, secret) {
  if (!header || !secret) return false;
  const parts = {};
  for (const kv of header.split(';')) {
    const i = kv.indexOf('=');
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  }
  if (!parts.ts || !parts.h1) return false;
  const ts = parseInt(parts.ts, 10);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false; // 5-min replay window
  const expected = crypto.createHmac('sha256', secret).update(`${parts.ts}:${rawBody}`).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parts.h1, 'hex'));
  } catch (e) { return false; }
}

async function paddleGet(path, apiKey) {
  const r = await fetch(`https://api.paddle.com${path}`, {
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
  });
  if (!r.ok) throw new Error(`Paddle API ${r.status} on ${path}`);
  return r.json();
}

async function sendKeyEmail(to, key, planLabel, resendKey, from) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: from || 'OpenX Pro <pro@openx-mo.vercel.app>',
      to: [to],
      subject: 'Your OpenX Pro licence key',
      text:
        `Thanks for buying OpenX Pro (${planLabel})!\n\n` +
        `Your licence key:\n\n${key}\n\n` +
        `Open any OpenX tool, open the Pro dialog and enter the key to unlock Pro on that device.\n\n` +
        `Keep this key safe — it is your proof of purchase. If you did not make this purchase, reply to this email.\n\n` +
        `— OpenX (Mountain Grey Design LTD.)`,
    }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
}

// Is this the first transaction for the subscription? Renewals must not re-email.
async function isFirstSubscriptionTransaction(subscriptionId, apiKey) {
  try {
    const j = await paddleGet(`/transactions?subscription_id=${encodeURIComponent(subscriptionId)}&per_page=2`, apiKey);
    const list = (j && j.data) || [];
    return list.length <= 1;
  } catch (e) {
    return true; // if we cannot check, send the key rather than lose it
  }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function handleEvent(event) {
  const type = event.event_type;
  const data = event.data || {};
  const log = (...a) => console.log('[paddle-webhook]', ...a);

  if (type === 'transaction.completed') {
    const secret = (process.env.PRO_SECRET || '').trim();
    if (!secret) { log('PRO_SECRET missing, cannot mint key'); return { ok: false, reason: 'no-pro-secret' }; }
    const subId = data.subscription_id || null;
    const txnId = data.id || '';
    const ref = subId ? `sub:${subId}` : `txn:${txnId}`;
    const key = mintKeyFor(ref, secret);
    const priceId = (data.items && data.items[0] && data.items[0].price && data.items[0].price.id) || '';
    const planLabel = subId ? 'subscription' : 'Lifetime';
    log(`transaction.completed price=${priceId} sub=${subId || '-'} txn=${txnId} key=${key}`);

    // Renewals: same key, no new email.
    if (subId && process.env.PADDLE_API_KEY) {
      const first = await isFirstSubscriptionTransaction(subId, process.env.PADDLE_API_KEY);
      if (!first) { log('renewal, key unchanged, no email'); return { ok: true, emailed: false, renewal: true }; }
    }

    // Resolve buyer email via Paddle API (webhooks carry customer_id, not email).
    let email = null;
    if (process.env.PADDLE_API_KEY && data.customer_id) {
      try {
        const c = await paddleGet(`/customers/${encodeURIComponent(data.customer_id)}`, process.env.PADDLE_API_KEY);
        email = c && c.data && c.data.email;
      } catch (e) { log('customer lookup failed:', e.message); }
    }
    if (!email) { log('no buyer email resolved; key only in logs'); return { ok: true, emailed: false, keyLogged: true }; }
    if (!process.env.RESEND_API_KEY) { log('RESEND_API_KEY missing; key only in logs'); return { ok: true, emailed: false, keyLogged: true }; }
    await sendKeyEmail(email, key, planLabel, process.env.RESEND_API_KEY, process.env.KEY_FROM_EMAIL);
    log(`key emailed to ${email}`);
    return { ok: true, emailed: true };
  }

  if (type === 'subscription.canceled' || type === 'adjustment.created') {
    // v1: log for manual revocation. The key keeps validating until a status
    // check is built; handle refunds/cancellations by hand for now.
    log(`${type} sub=${data.subscription_id || '-'} txn=${data.transaction_id || data.id || '-'}`);
    return { ok: true, noted: true };
  }

  log(`ignored ${type}`);
  return { ok: true, ignored: true };
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Paddle-Signature');
  if (req.method === 'OPTIONS') { res.status(200).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'POST only' }); return; }
  try {
    const raw = await readRawBody(req);
    if (!verifySignature(raw, req.headers['paddle-signature'], (process.env.PADDLE_WEBHOOK_SECRET || '').trim())) {
      res.status(401).json({ ok: false, error: 'bad signature' });
      return;
    }
    let event;
    try { event = JSON.parse(raw); } catch (e) { res.status(400).json({ ok: false, error: 'bad json' }); return; }
    const result = await handleEvent(event);
    res.status(200).json({ ok: true, ...result });
  } catch (e) {
    console.error('[paddle-webhook] error:', e);
    res.status(500).json({ ok: false, error: 'handler error' });
  }
};

// Exported for local testing.
module.exports._test = { verifySignature, mintKeyFor, b32enc };
