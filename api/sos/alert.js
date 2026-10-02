// Serverless Function: /api/sos/alert
// Dispatches emergency alerts to verified providers (n8n / WhatsApp Cloud API)
// Includes abuse protection: IP rate limiting, device token HMAC verification, body size limits, and E.164 validation

import { verifyDeviceToken } from '../device/register.js';

// E.164 international phone number format (+ followed by 7 to 15 digits)
const E164_REGEX = /^\+[1-9]\d{6,14}$/;

function normalizeToE164(phone) {
  if (!phone) return '';
  const digits = phone.toString().replace(/[^0-9]/g, '');
  if (!digits) return '';
  if (digits.length === 12 && digits.startsWith('91')) return `+${digits}`;
  if (digits.length === 10) return `+91${digits}`;
  return `+${digits}`;
}

// In-memory rate limiting fallback if Redis/KV is not configured
const inMemoryRateLimits = new Map();
function checkInMemoryRateLimit(ip) {
  const now = Date.now();
  const record = inMemoryRateLimits.get(ip) || { count: 0, resetAt: now + 60000 };

  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + 60000;
  } else {
    record.count += 1;
  }

  inMemoryRateLimits.set(ip, record);

  // Clean old entries periodically
  if (inMemoryRateLimits.size > 1000) {
    for (const [k, v] of inMemoryRateLimits.entries()) {
      if (now > v.resetAt) inMemoryRateLimits.delete(k);
    }
  }

  return record.count <= 5;
}

async function checkRateLimit(ip) {
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (!kvUrl || !kvToken) {
    return checkInMemoryRateLimit(ip);
  }

  try {
    const key = `ratelimit:sos:${ip}`;
    const res = await fetch(`${kvUrl}/pipeline`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${kvToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([
        ['INCR', key],
        ['EXPIRE', key, 60]
      ]),
      signal: AbortSignal.timeout(3000)
    });

    if (res.ok) {
      const data = await res.json();
      const count = data?.[0]?.result;
      if (typeof count === 'number') {
        return count <= 5;
      }
    }
    return checkInMemoryRateLimit(ip);
  } catch (err) {
    console.warn('KV rate limit check failed, using fallback:', err.message);
    return checkInMemoryRateLimit(ip);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // 1. Max Body Size Enforcement (32 KB limit)
  const rawBodySize = JSON.stringify(req.body || {}).length;
  if (rawBodySize > 32768) {
    return res.status(413).json({ error: 'Payload Too Large. Maximum allowed size is 32KB.' });
  }

  // 2. Client Device Authentication Token Verification
  const deviceToken = req.headers['x-device-token'] || req.body?.deviceToken;
  if (!deviceToken || !verifyDeviceToken(deviceToken)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing device token. Register via /api/device/register.' });
  }

  // 3. Per-IP Rate Limiting (max 5 alerts per minute)
  const clientIp = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1').split(',')[0].trim();
  const withinLimit = await checkRateLimit(clientIp);
  if (!withinLimit) {
    return res.status(429).json({ error: 'Rate limit exceeded: Too many SOS alerts dispatched. Please wait one minute.' });
  }

  try {
    const { sessionId, location, contacts, timestamp, liveTrackingUrl, userPhone } = req.body || {};

    const rawContacts = Array.isArray(contacts) ? contacts : [];

    // 4. Maximum 5 contacts validation
    if (rawContacts.length > 5) {
      return res.status(400).json({ error: 'Validation Error: A maximum of 5 emergency contacts can be alerted.' });
    }

    // 5. Contact phone E.164 validation
    const recipients = [];
    for (const c of rawContacts) {
      const normalizedPhone = normalizeToE164(c.phone || c.contactNumber);
      if (!normalizedPhone || !E164_REGEX.test(normalizedPhone)) {
        return res.status(400).json({
          error: `Validation Error: Contact "${c.name || 'Unknown'}" has an invalid phone number (${c.phone}). Must be in valid E.164 international format.`
        });
      }
      recipients.push({
        id: c.id || c.contactId,
        name: c.name || c.contactName || 'Emergency Contact',
        phone: normalizedPhone,
        relation: c.relation || 'Contact',
        isPrimary: !!c.isPrimary
      });
    }

    if (recipients.length === 0) {
      return res.status(400).json({ error: 'Validation Error: At least one valid emergency contact is required.' });
    }

    const formattedSystemNumber = normalizeToE164(userPhone) || 'Unknown User';

    const locationText = (location && typeof location.latitude === 'number' && typeof location.longitude === 'number')
      ? `https://www.google.com/maps?q=${location.latitude},${location.longitude}`
      : (liveTrackingUrl || 'Location currently unavailable (GPS acquiring...)');

    const messageBody = `🚨 *EMERGENCY ALERT*\n\nSOS has been activated.\n\n*User Phone:*\n${formattedSystemNumber}\n\nI need help.\n\n📍 *Location / Tracking:*\n${locationText}\n\nPlease contact me immediately.`;

    const results = [];
    let providerConfigured = false;

    // 6. Provider A: n8n Cloud Webhook Forwarding (Server-side)
    const n8nWebhookUrl = process.env.N8N_WEBHOOK_URL;
    const n8nWebhookSecret = process.env.N8N_WEBHOOK_SECRET || '';

    if (n8nWebhookUrl) {
      providerConfigured = true;
      try {
        const n8nRes = await fetch(n8nWebhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(n8nWebhookSecret ? { 'X-Webhook-Secret': n8nWebhookSecret } : {})
          },
          body: JSON.stringify({
            sessionId,
            location: location || null,
            userPhone: formattedSystemNumber,
            recipients,
            message: messageBody,
            liveTrackingUrl: liveTrackingUrl || null,
            timestamp: timestamp || new Date().toISOString()
          }),
          signal: AbortSignal.timeout(8000)
        });

        if (n8nRes.ok) {
          recipients.forEach(c => {
            results.push({ id: c.id, phone: c.phone, status: 'SENT', provider: 'n8n Webhook' });
          });
        } else {
          const errText = await n8nRes.text().catch(() => '');
          console.warn(`n8n webhook dispatch rejected [${n8nRes.status}]:`, errText);
          recipients.forEach(c => {
            results.push({ id: c.id, phone: c.phone, status: 'FAILED', error: `n8n returned HTTP ${n8nRes.status}` });
          });
        }
      } catch (n8nErr) {
        console.warn('n8n webhook network error:', n8nErr.message);
        recipients.forEach(c => {
          results.push({ id: c.id, phone: c.phone, status: 'FAILED', error: n8nErr.message });
        });
      }
    }

    // 7. Provider B: WhatsApp Cloud API (if configured)
    const waToken = process.env.WHATSAPP_ACCESS_TOKEN || process.env.WHATSAPP_API_KEY;
    const waPhoneId = process.env.WHATSAPP_PHONE_NUMBER_ID || process.env.WHATSAPP_SENDER_ID;

    if (waToken && waPhoneId) {
      providerConfigured = true;
      for (const contact of recipients) {
        // If already succeeded via n8n, don't duplicate unless desired
        const existingSuccess = results.find(r => r.id === contact.id && r.status === 'SENT');
        if (existingSuccess) continue;

        const cleanRecipientDigits = contact.phone.replace(/[^0-9]/g, '');
        try {
          const waRes = await fetch(`https://graph.facebook.com/v19.0/${waPhoneId}/messages`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${waToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              messaging_product: 'whatsapp',
              to: cleanRecipientDigits,
              type: 'text',
              text: { body: messageBody }
            }),
            signal: AbortSignal.timeout(8000)
          });

          if (waRes.ok) {
            results.push({ id: contact.id, phone: contact.phone, status: 'SENT', provider: 'WhatsApp Cloud API' });
          } else {
            const errData = await waRes.json().catch(() => ({}));
            console.warn(`WhatsApp send failed for ${contact.phone}:`, errData);
            results.push({ id: contact.id, phone: contact.phone, status: 'FAILED', error: errData.error?.message || 'WhatsApp API rejection' });
          }
        } catch (waErr) {
          results.push({ id: contact.id, phone: contact.phone, status: 'FAILED', error: waErr.message });
        }
      }
    }

    // 8. If NO provider credentials exist: return 503 error honestly (DO NOT report fake SENT)
    if (!providerConfigured) {
      return res.status(503).json({
        success: false,
        status: 'FAILED',
        error: 'Emergency alert service unavailable: No dispatch providers configured on the server. Configure N8N_WEBHOOK_URL or WhatsApp API in environment variables.',
        results: recipients.map(c => ({
          id: c.id,
          phone: c.phone,
          status: 'FAILED',
          error: 'No dispatch provider configured on server'
        }))
      });
    }

    const deliveredCount = results.filter(r => r.status === 'SENT').length;
    const isOverallSuccess = deliveredCount > 0;

    return res.status(isOverallSuccess ? 200 : 502).json({
      success: isOverallSuccess,
      status: isOverallSuccess ? 'SENT' : 'FAILED',
      deliveredCount,
      results,
      messageBody
    });
  } catch (err) {
    console.error('Fatal error in /api/sos/alert:', err);
    return res.status(500).json({
      success: false,
      status: 'FAILED',
      error: 'Emergency alert dispatch failed due to internal server error.'
    });
  }
}
