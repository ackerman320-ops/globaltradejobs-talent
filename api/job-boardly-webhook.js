// api/job-boardly-webhook.js
//
// Receives Job Boardly's signed webhook when a candidate registers,
// then adds them to an EmailOctopus list. EmailOctopus's own automation
// (trigger: contact subscribed -> delay 24-48h -> send email) handles
// the actual send, so this function's only job is "get them into the list."
//
// ENV VARS TO SET IN VERCEL:
//   JOB_BOARDLY_SIGNING_SECRET   - "Application webhook signing secret" from
//                                   Job Boardly > Settings > Board > Integrations > Webhooks.
//                                   Confirmed: the same secret signs both the
//                                   application AND candidate.registered events.
//   EMAILOCTOPUS_API_KEY         - from EmailOctopus > Settings > API
//   EMAILOCTOPUS_LIST_ID         - the list new candidates get added to
//
// NOTE: written in CommonJS (require/module.exports), not ES modules
// (import/export). This repo has no package.json declaring
// "type": "module", so Vercel's Node.js runtime parses .js files as
// CommonJS by default.

const crypto = require('crypto');

const JOB_BOARDLY_SIGNING_SECRET = process.env.JOB_BOARDLY_SIGNING_SECRET;
const EMAILOCTOPUS_API_KEY = process.env.EMAILOCTOPUS_API_KEY;
const EMAILOCTOPUS_LIST_ID = process.env.EMAILOCTOPUS_LIST_ID;

// Vercel needs the raw body to verify the HMAC signature, so we turn off
// the default body parser and read the stream ourselves.
const config = {
  api: {
    bodyParser: false,
  },
};

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function verifySignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader) return false;

  // Header format is "sha256=<hex hmac of raw body>"
  const [scheme, providedHex] = signatureHeader.split('=');
  if (scheme !== 'sha256' || !providedHex) return false;

  const expectedHex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const providedBuf = Buffer.from(providedHex, 'hex');
  if (expectedBuf.length !== providedBuf.length) return false;

  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).send('Method not allowed');
  }

  const rawBody = await getRawBody(req);
  const signature = req.headers['x-jobboardly-signature'];
  const eventType = req.headers['x-jobboardly-event'];

  if (!verifySignature(rawBody, signature, JOB_BOARDLY_SIGNING_SECRET)) {
    console.warn('Job Boardly webhook: signature verification failed');
    return res.status(401).send('Invalid signature');
  }

  if (eventType !== 'candidate.registered') {
    // This endpoint should only ever be wired to the "New candidate
    // registration" webhook, but bail out safely just in case.
    return res.status(200).send('Ignored - not a registration event');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return res.status(400).send('Invalid JSON');
  }

  const candidate = payload.candidate || {};
  const email = candidate.email;
  const firstName = candidate.first_name || '';
  const lastName = candidate.last_name || '';

  // Optional: only nurture profiles that have cleared moderation.
  // Uncomment if you'd rather wait until a profile is approved before
  // adding them to the course-recommendation list.
  // if (candidate.approval_state !== 'approved') {
  //   return res.status(200).send('Ignored - not yet approved');
  // }

  if (!email) {
    console.warn('Job Boardly webhook: no candidate email in payload', payload);
    return res.status(400).send('No email in payload');
  }

  const eoResponse = await fetch(
    `https://api.emailoctopus.com/lists/${EMAILOCTOPUS_LIST_ID}/contacts`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${EMAILOCTOPUS_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email_address: email,
        fields: {
          // Field keys must match your EmailOctopus list's field names
          // exactly (that list's Settings -> Fields) - adjust if needed.
          FirstName: firstName,
          LastName: lastName,
        },
        status: 'subscribed',
        tags: ['new-signup-course-nurture'],
      }),
    }
  );

  if (eoResponse.ok) {
    return res.status(200).send('OK');
  }

  // Job Boardly's docs note it may redeliver the same candidate.id on
  // retry - treat "already a member" as success, not an error.
  const errBody = await eoResponse.json().catch(() => ({}));
  const alreadyMember =
    eoResponse.status === 409 ||
    errBody?.error?.code === 'MEMBER_EXISTS_WITH_EMAIL_ADDRESS';

  if (alreadyMember) {
    return res.status(200).send('OK - already subscribed');
  }

  console.error('EmailOctopus add-contact failed:', eoResponse.status, errBody);
  // Still 200 to Job Boardly so it doesn't retry-storm the endpoint;
  // the error is logged in Vercel for you to catch.
  return res.status(200).send('Received, but EmailOctopus add failed - check logs');
}

module.exports = handler;
module.exports.config = config;
