// Serverless Function: /api/device/register
// Issues signed HMAC device tokens to prevent unauthorized SOS dispatch abuse

import crypto from 'crypto';

const DEVICE_SECRET = process.env.DEVICE_AUTH_SECRET || process.env.N8N_WEBHOOK_SECRET || 'saferoute-device-auth-key-default';

export function signDeviceId(deviceId) {
  return crypto.createHmac('sha256', DEVICE_SECRET).update(deviceId).digest('hex');
}

export function verifyDeviceToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [deviceId, signature] = parts;
  if (!deviceId || !signature) return false;

  const expected = signDeviceId(deviceId);
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const requestedId = req.body?.deviceId;
    const deviceId = (typeof requestedId === 'string' && requestedId.trim().length >= 8 && requestedId.length <= 64)
      ? requestedId.trim()
      : crypto.randomUUID();

    const signature = signDeviceId(deviceId);
    const token = `${deviceId}.${signature}`;

    return res.status(200).json({
      success: true,
      deviceId,
      token,
      issuedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('Device registration error:', err);
    return res.status(500).json({ error: 'Failed to issue device token' });
  }
}
